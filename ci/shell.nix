let
  pkgs = (import <nixpkgs> {});
in
import ./mkshell.nix { inherit pkgs; }
