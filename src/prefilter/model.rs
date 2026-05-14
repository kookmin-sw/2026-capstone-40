//! XGBoost native-JSON loader + tree-walk inference. Pure-Rust, no `xgboost`
//! crate dependency.
//!
//! Supported schema: XGBoost ≥ 1.0 native JSON (`booster.save_model("x.json")`).
//! Each tree stores parallel arrays (`left_children`, `split_indices`,
//! `split_conditions`, `default_left`, `base_weights`); leaves are nodes whose
//! `left_children == -1`. Multiclass routing comes from `tree_info[]` —
//! one entry per tree giving the class that tree contributes to.
//!
//! For `multi:softprob`, raw class scores are summed across the relevant trees
//! and passed through softmax. `base_score` is an additive offset that cancels
//! under softmax, so we omit it.

use std::path::Path;

use serde_json::Value;

#[derive(Debug, Clone, Copy)]
pub struct Node {
    pub feature: i32,        // split feature index, -1 if leaf
    pub threshold: f32,
    pub left: i32,           // -1 if leaf
    pub right: i32,
    pub default_left: bool,
    pub leaf_value: f32,     // base_weights[node]
}

#[derive(Debug, Clone)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

impl Tree {
    pub fn predict(&self, feat: &[f32]) -> f32 {
        let mut idx = 0i32;
        loop {
            let n = &self.nodes[idx as usize];
            if n.left < 0 {
                return n.leaf_value;
            }
            let fi = n.feature as usize;
            let next = if fi < feat.len() {
                let v = feat[fi];
                if v.is_nan() {
                    if n.default_left { n.left } else { n.right }
                } else if v < n.threshold {
                    n.left
                } else {
                    n.right
                }
            } else if n.default_left {
                n.left
            } else {
                n.right
            };
            idx = next;
        }
    }
}

#[derive(Debug, Clone)]
pub struct Booster {
    pub trees: Vec<Tree>,
    pub tree_info: Vec<u32>,   // class index per tree; len == trees.len()
    pub base_score: Vec<f32>,  // per-class bias; XGBoost 3.x stores as vector string
    pub num_class: u32,
    pub num_feature: u32,
}

#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Schema(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Schema(e) => write!(f, "schema: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<serde_json::Error> for LoadError {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}

impl Booster {
    pub fn load_json_file(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path)?;
        Self::load_json_str(&text)
    }

    pub fn load_json_str(text: &str) -> Result<Self, LoadError> {
        let v: Value = serde_json::from_str(text)?;
        let learner = v.get("learner").ok_or_else(|| LoadError::Schema("missing 'learner'".into()))?;

        let lmp = learner
            .get("learner_model_param")
            .ok_or_else(|| LoadError::Schema("missing learner_model_param".into()))?;
        let num_class = parse_string_u32(lmp.get("num_class")).unwrap_or(1).max(1);
        let num_feature = parse_string_u32(lmp.get("num_feature")).unwrap_or(0);
        let base_score = parse_base_score(lmp.get("base_score"), num_class);

        let gb = learner
            .get("gradient_booster")
            .and_then(|g| g.get("model"))
            .ok_or_else(|| LoadError::Schema("missing gradient_booster.model".into()))?;

        let trees_v = gb
            .get("trees")
            .and_then(|t| t.as_array())
            .ok_or_else(|| LoadError::Schema("missing trees[]".into()))?;

        let mut trees: Vec<Tree> = Vec::with_capacity(trees_v.len());
        for t in trees_v {
            trees.push(parse_tree(t)?);
        }

        let tree_info: Vec<u32> = match gb.get("tree_info").and_then(|x| x.as_array()) {
            Some(arr) => arr
                .iter()
                .map(|v| v.as_u64().unwrap_or(0) as u32)
                .collect(),
            None => {
                if num_class > 1 {
                    return Err(LoadError::Schema(
                        "tree_info[] required for multi-class booster".into(),
                    ));
                }
                vec![0; trees.len()]
            }
        };

        if tree_info.len() != trees.len() {
            return Err(LoadError::Schema(format!(
                "tree_info len {} != trees len {}",
                tree_info.len(),
                trees.len()
            )));
        }

        Ok(Booster { trees, tree_info, base_score, num_class, num_feature })
    }

    /// Sum leaf values per class across all trees, plus per-class base_score.
    pub fn raw_scores(&self, feat: &[f32]) -> Vec<f32> {
        let nc = self.num_class as usize;
        let mut raw = if self.base_score.len() == nc {
            self.base_score.clone()
        } else {
            vec![0.0f32; nc]
        };
        for (t, &cls) in self.trees.iter().zip(self.tree_info.iter()) {
            raw[cls as usize] += t.predict(feat);
        }
        raw
    }

    /// Numerically stable softmax over raw scores → probability vector.
    pub fn predict_proba(&self, feat: &[f32]) -> Vec<f32> {
        softmax(&self.raw_scores(feat))
    }
}

fn softmax(raw: &[f32]) -> Vec<f32> {
    if raw.is_empty() { return vec![]; }
    let m = raw.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let mut out: Vec<f32> = raw.iter().map(|x| (x - m).exp()).collect();
    let s: f32 = out.iter().sum();
    if s > 0.0 {
        for v in out.iter_mut() { *v /= s; }
    }
    out
}

/// Parse XGBoost `base_score` which in 3.x is stored as either:
///   - A plain float string `"0.5"` (scalar, applies uniformly)
///   - A bracketed list string `"[a,b,c,d]"` (per-class vector)
///
/// XGBoost 3.x applies the per-class base score in logit/log space depending on
/// objective; for multi:softprob the values are already in the correct additive
/// space used during gradient boosting, so we add them directly to raw scores.
fn parse_base_score(v: Option<&Value>, num_class: u32) -> Vec<f32> {
    let s = match v.and_then(|x| x.as_str()) {
        Some(s) => s.trim().to_owned(),
        None => return vec![0.0f32; num_class as usize],
    };
    if s.starts_with('[') {
        let inner = s.trim_start_matches('[').trim_end_matches(']');
        let vals: Vec<f32> = inner
            .split(',')
            .filter_map(|tok| tok.trim().parse::<f32>().ok())
            .collect();
        if vals.len() == num_class as usize { return vals; }
        // length mismatch → ignore
        vec![0.0f32; num_class as usize]
    } else {
        let scalar: f32 = s.parse().unwrap_or(0.0);
        vec![scalar; num_class as usize]
    }
}

fn parse_string_u32(v: Option<&Value>) -> Option<u32> {
    let v = v?;
    if let Some(n) = v.as_u64() { return Some(n as u32); }
    if let Some(s) = v.as_str() { return s.parse::<u32>().ok(); }
    None
}

fn parse_tree(t: &Value) -> Result<Tree, LoadError> {
    let left = arr_i32(t, "left_children")?;
    let right = arr_i32(t, "right_children")?;
    let split_idx = arr_i32(t, "split_indices")?;
    let split_cond = arr_f32(t, "split_conditions")?;
    let base_w = arr_f32(t, "base_weights")?;
    let default_left = arr_bool_or_int(t, "default_left")?;

    let n = left.len();
    if right.len() != n
        || split_idx.len() != n
        || split_cond.len() != n
        || base_w.len() != n
        || default_left.len() != n
    {
        return Err(LoadError::Schema("tree array length mismatch".into()));
    }

    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let is_leaf = left[i] < 0;
        nodes.push(Node {
            feature: if is_leaf { -1 } else { split_idx[i] },
            threshold: split_cond[i],
            left: left[i],
            right: right[i],
            default_left: default_left[i],
            leaf_value: base_w[i],
        });
    }
    Ok(Tree { nodes })
}

fn arr_i32(t: &Value, key: &str) -> Result<Vec<i32>, LoadError> {
    let arr = t
        .get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| LoadError::Schema(format!("missing {key}")))?;
    Ok(arr.iter().map(|v| v.as_i64().unwrap_or(-1) as i32).collect())
}

fn arr_f32(t: &Value, key: &str) -> Result<Vec<f32>, LoadError> {
    let arr = t
        .get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| LoadError::Schema(format!("missing {key}")))?;
    Ok(arr.iter().map(|v| v.as_f64().unwrap_or(0.0) as f32).collect())
}

fn arr_bool_or_int(t: &Value, key: &str) -> Result<Vec<bool>, LoadError> {
    let arr = t
        .get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| LoadError::Schema(format!("missing {key}")))?;
    Ok(arr
        .iter()
        .map(|v| {
            if let Some(b) = v.as_bool() { return b; }
            if let Some(n) = v.as_u64() { return n != 0; }
            if let Some(n) = v.as_i64() { return n != 0; }
            false
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single-tree single-class stump:
    /// node 0: split on feat[0] < 1.5 → left=1, right=2
    /// leaves: 1 = -2.0, 2 = +3.0
    fn one_class_stump() -> &'static str {
        r#"{
  "version": [2, 0, 0],
  "learner": {
    "learner_model_param": {"num_class": "0", "num_feature": "1", "base_score": "0.0"},
    "gradient_booster": {
      "name": "gbtree",
      "model": {
        "gbtree_model_param": {"num_trees": "1"},
        "trees": [{
          "id": 0,
          "left_children":   [1, -1, -1],
          "right_children":  [2, -1, -1],
          "split_indices":   [0,  0,  0],
          "split_conditions":[1.5, 0.0, 0.0],
          "default_left":    [false, false, false],
          "base_weights":    [0.0, -2.0, 3.0]
        }],
        "tree_info": [0]
      }
    }
  }
}"#
    }

    #[test]
    fn loads_and_predicts_stump() {
        let b = Booster::load_json_str(one_class_stump()).unwrap();
        assert_eq!(b.trees.len(), 1);
        assert_eq!(b.num_class, 1);
        // num_class=0 in raw param → bumped to 1
        let p = b.predict_proba(&[0.0]);
        assert_eq!(p, vec![1.0]); // single-class softmax = 1.0

        // Routing test via raw_scores
        assert_eq!(b.raw_scores(&[0.0])[0], -2.0);
        assert_eq!(b.raw_scores(&[2.0])[0], 3.0);
    }

    /// 3-class booster with 3 trees (one per class), each a single-leaf tree.
    /// Class scores: [1.0, 2.0, 3.0] regardless of input → softmax fixed.
    fn three_class_stub() -> &'static str {
        r#"{
  "learner": {
    "learner_model_param": {"num_class": "3", "num_feature": "2"},
    "gradient_booster": {"name": "gbtree", "model": {
      "trees": [
        {"left_children":[-1],"right_children":[-1],"split_indices":[0],
         "split_conditions":[0.0],"default_left":[false],"base_weights":[1.0]},
        {"left_children":[-1],"right_children":[-1],"split_indices":[0],
         "split_conditions":[0.0],"default_left":[false],"base_weights":[2.0]},
        {"left_children":[-1],"right_children":[-1],"split_indices":[0],
         "split_conditions":[0.0],"default_left":[false],"base_weights":[3.0]}
      ],
      "tree_info": [0, 1, 2]
    }}
  }
}"#
    }

    #[test]
    fn multiclass_softmax() {
        let b = Booster::load_json_str(three_class_stub()).unwrap();
        let p = b.predict_proba(&[0.0, 0.0]);
        // Reference softmax([1,2,3])
        let raw = [1.0f32, 2.0, 3.0];
        let m = 3.0f32;
        let exps: Vec<f32> = raw.iter().map(|x| (x - m).exp()).collect();
        let s: f32 = exps.iter().sum();
        let want: Vec<f32> = exps.iter().map(|e| e / s).collect();
        for (a, b) in p.iter().zip(want.iter()) {
            assert!((a - b).abs() < 1e-6, "got {p:?} want {want:?}");
        }
    }

    #[test]
    fn nan_uses_default_left() {
        let json = r#"{
  "learner": {
    "learner_model_param": {"num_class": "0", "num_feature": "1"},
    "gradient_booster": {"name": "gbtree", "model": {
      "trees": [{
        "left_children":[1,-1,-1], "right_children":[2,-1,-1],
        "split_indices":[0,0,0], "split_conditions":[0.5,0.0,0.0],
        "default_left":[true,false,false],
        "base_weights":[0.0,-1.0,1.0]
      }],
      "tree_info":[0]
    }}
  }
}"#;
        let b = Booster::load_json_str(json).unwrap();
        assert_eq!(b.raw_scores(&[f32::NAN])[0], -1.0);
    }
}
