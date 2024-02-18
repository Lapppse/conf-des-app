# BIG DATA BSUIR anonymization implementation compatible with [the Republic of Belarus laws](https://pravo.by/document/?guid=12551&p0=H12100099)
This repo is only an example of data anonymization by introducing an identifier.
In short, the method works by replacing sensitive data with an identifier and doing vice-versa when the actual info is needed.
This method lets to secure the database in such way that when it's leaked intruder won't be able to get any useful info.

## Requirements
To run any version of the app, you need to have [Rust](https://www.rust-lang.org/) installed.

## Executing
Navigate to the project folder.  

To run the GUI version of the app, execute
```sh
cargo run --release --bin app
```
To run the console version of the app, execute
```sh
cargo run --release --bin console-app
```
