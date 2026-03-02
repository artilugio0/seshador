{
  description = "Go shell";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... } :
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go
          gopls
          gotools

          libGL
          libxkbcommon
          pkg-config
          xorg.libX11.dev
          xorg.libXcursor
          xorg.libXi
          xorg.libXinerama
          xorg.libXrandr
          xorg.libXxf86vm
        ];
      };
    };
}
