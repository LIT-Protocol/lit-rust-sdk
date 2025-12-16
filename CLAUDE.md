The goal of this project is to create a Rust SDK that lets you use Lit Protocol. There is a rust project that implements a limited version of the SDK at `lit-peer/rust/lit-node/lit-sdk`. We should import that and use as much of it as possible, and not rewrite anything that's already in that project.

There is an existing JS SDK in the `js-sdk` folder which you can use as a reference when creating the rust SDK. Docs are available at https://naga.developer.litprotocol.com/sdk/introduction and the typedocs are at https://naga.developer.litprotocol.com/sdk/sdk-reference/lit-client/functions/createLitClient

Additionally, there the lit node implementation itself, in rust, in the lit-peer/rust/lit-node/lit-node folder. It has various tests in it that you can use as a reference for working rust code that talks to the Lit Nodes.

You can run the tests of this new Rust SDK by running `cargo test -- -nocapture` in the lit-rust-sdk folder. The tests should connect to real lit nodes and make real HTTP requests, etc. Do not mock anything in the tests.

Always run `cargo fmt` when you're done with a task so that the files have consistent formatting.

Currently, the project is working with the Datil network, and works like the JS v7 SDK. We are launching a new network called Naga, and the new v8 version of the JS SDK is in the `js-sdk` folder. We need to update our rust SDK to work with the Naga network. Naga is not backwards compatible with Datil, so you can remove Datil support. Try to vaguely match the interface of the v7 JS SDK if possible.
