let
  pkgs = (import <nixpkgs> {}).pkgsi686Linux;
in
import ./mkshell.nix { inherit pkgs; }
