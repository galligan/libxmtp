{
  rustPlatform,
  pkg-config,
  fetchCrate,
  curl,
  nodejs_latest,
  openssl,
  stdenv,
  lib,
}:
let
  src = fetchCrate {
    pname = "wasm-bindgen-cli";
    version = "0.2.116";
    hash = "sha256-Pcb5+dEaWK+SQJz73/3Si0kxEy8y8n21t+DETMdvKHc=";
  };

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit src;
    inherit (src) pname version;
    hash = "sha256-PztHuoWBh+wqOuSFTQxnnddKSSu0S1MBOgKy0szHQpI=";
  };
in
rustPlatform.buildRustPackage {
  pname = "wasm-bindgen-cli";

  inherit src cargoDeps;
  inherit (src) version;

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [
    openssl
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin [
    curl
  ];

  nativeCheckInputs = [ nodejs_latest ];

  # tests require it to be ran in the wasm-bindgen monorepo
  doCheck = false;
  meta = {
    description = "Custom maintained wasm-bindgen-cli package to match Cargo.toml";
  };
}
