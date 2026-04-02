{ self, inputs, ... }:
{
  perSystem =
    {
      pkgs,
      system,
      lib,
      ...
    }:
    let
      sdkConfig = {
        darwinSdkVersion = "14.3";
        xcodeVer = "26";
        useIOSPrebuilt = true;
      };

      # Single source of truth: ABI name → target config
      iosTargets = {
        "aarch64-darwin" = {
          config = "arm64-apple-darwin";
          rust.rustcTarget = "aarch64-apple-darwin";
        };
        "x86_64-darwin" = {
          config = "x86_64-apple-darwin";
          rust.rustcTarget = "x86_64-apple-darwin";
        };
        "iphone64" = {
          config = "arm64-apple-ios";
          rust.rustcTarget = "aarch64-apple-ios";
        };
        "iphone64-simulator" = {
          config = "arm64-apple-ios";
          rust.rustcTarget = "aarch64-apple-ios-sim";
        };
      };

      # config name → ABI name
      configToAbi = lib.listToAttrs (
        lib.mapAttrsToList (abi: t: {
          name = t.config;
          value = abi;
        }) iosTargets
      );

      crossPkgs = self.lib.mkCrossPkgs system (lib.mapAttrsToList (_: t: t // sdkConfig) iosTargets);
      mkIosBindings = p: p.callPackage ./package/ios-bindings.nix;

      # Per-target dylibs keyed by config name
      iosDylibs = lib.mapAttrs (_: p: (mkIosBindings p { }).dylib) crossPkgs;

      # Swift bindings from host build
      inherit (mkIosBindings pkgs { }) swift-bindings;

      fastAbi =
        if pkgs.stdenv.hostPlatform.isx86_64 then
          "x86_64-darwin"
        else if pkgs.stdenv.hostPlatform.isAarch64 then
          "aarch64-darwin"
        else
          throw "Unsupported host architecture for android-libs-fast";

      fastTarget = iosTargets.${fastAbi};
      fastDylib = iosDylibs.${fastTarget.config};

      ios-libs-fast = pkgs.linkFarm "xmtpv3-android-fast" [
        {
          name = "jniLibs/${fastAbi}/libuniffi_xmtpv3.so";
          path = "${fastDylib}/libuniffi_xmtpv3.so";
        }
        {
          name = "java/uniffi/xmtpv3/xmtpv3.kt";
          path = "${swift-bindings}/kotlin/uniffi/xmtpv3/xmtpv3.kt";
        }
        {
          name = "libxmtp-version.txt";
          path = "${swift-bindings}/libxmtp-version.txt";
        }
      ];

      # Aggregate all targets + Swift bindings into a Gradle-ready layout
      ios-libs = pkgs.linkFarm "xmtpv3-android" (
        lib.mapAttrsToList (config: dylib: {
          name = "jniLibs/${configToAbi.${config}}/libuniffi_xmtpv3.so";
          path = "${dylib}/libuniffi_xmtpv3.so";
        }) iosDylibs
        ++ [
          {
            name = "java/uniffi/xmtpv3/xmtpv3.kt";
            path = "${swift-bindings}/kotlin/uniffi/xmtpv3/xmtpv3.kt";
          }
          {
            name = "libxmtp-version.txt";
            path = "${swift-bindings}/libxmtp-version.txt";
          }
        ]
      );
    in
    {
      packages = {
        # inherit ios-libs ios-libs-fast swift-bindings;
        inherit swift-bindings;

      }
      // lib.mapAttrs' (config: dylib: {
        name = "android-bindings-${configToAbi.${config}}";
        value = dylib;
      }) iosDylibs;
    };
}
