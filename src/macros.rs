#[macro_export]
macro_rules! read {
    ($statement:literal, $return_type:ty) => {{
        print!("{}: ", $statement);
        io::stdout().flush().expect("flush failed!");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        input.trim().parse::<$return_type>().unwrap()
    }};
}
