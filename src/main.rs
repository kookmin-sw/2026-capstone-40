fn main() {
    capstone::logger::init();
    capstone::cli::run(std::env::args().skip(1));
}
