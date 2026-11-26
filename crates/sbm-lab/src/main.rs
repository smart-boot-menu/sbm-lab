fn main() {
    let code = match sbm_lab::cli::execute() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("sbm-lab: {err}");
            1
        }
    };
    std::process::exit(code);
}
