The goal of this project is to create a Rust SDK that lets you use Lit Protocol. There is already an existing JS SDK in the js-sdk folder. Please use that as a reference when creating the rust SDK. Docs are available at https://developer.litprotocol.com/ and the typedocs are at https://v7-api-doc-lit-js-sdk.vercel.app/

Additionally, there is a rust project (the lit node itself) in the lit-assets/rust/lit-node folder. It has various tests in it that you can use as a reference for working rust code that talks to the Lit Nodes.

You can run the tests of this new Rust SDK by running `cargo test -- -nocapture` in the lit-rust-sdk folder. The tests should connect to real lit nodes and make real HTTP requests, etc. Do not mock anything in the tests.

Always run `cargo fmt` when you're done with a task so that the files have consistent formatting.
