## WIP (Work in Progress)


This project provides high-performance cryptographic functions, written in Rust and compiled to WebAssembly (WASM), for use in a modern web application. 

The core Rust crate, `veruszsupportweb`, handles Zcash Sapling key generation and symmetric key derivation, which is then consumed by a Vue.js and TypeScript frontend.

This project performs a basic

**KA.DerivePublic**
**KA.Agree**
**KDF**


-----

## Prerequisites

Before you begin, ensure you have the following tools installed:

  * **Rust:** [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
  * **wasm-pack:** `cargo install wasm-pack`
  * **Vite Project:** (https://vite.dev/guide/)

-----

## Project Structure

The project is organized as follows:

  * **/veruszsupportweb/**: The native Rust crate containing all core cryptographic logic and WASM bindings.
  * zsupport (root): The Vue.js + TypeScript frontend application that consumes the WASM module.

-----

## Development Workflow

Follow these steps to build, test, and run the project.

### **1. Build the WebAssembly Module**

First, you must compile the Rust crate into a WebAssembly package.

```bash
# Navigate to the Rust crate directory
cd veruszsupportweb

# Build the WASM package
wasm-pack build --target web --release --out-dir pkg
```

This command compiles the Rust code and creates a self-contained NPM package in the `veruszsupportweb/pkg` directory.

### **2. Run Native Rust Tests**

To quickly verify the core cryptographic logic without needing a browser, you can run the native Rust unit tests. This is the fastest way to debug the Rust code.

```bash
# Ensure you are in the Rust crate directory
cd veruszsupportweb

# Run the tests
cargo test
```

A successful run will confirm that the internal logic (like the symmetric key derivation and comparison) is working correctly.

### **3. Integrate WASM with the Vue Project**


This copies the package into your `node_modules`. You must re-run this command every time you rebuild the WASM package.

```bash
# From your Vue project's root directory
npm install ./veruszsupportweb/pkg
```

### **4. Run the Vue + TypeScript Project**

Finally, install the frontend dependencies and start the development server.

```bash
# From your Vue project's root directory
npm install
npm run dev
```

You can now open your browser to the provided local URL and test the integrated application.
