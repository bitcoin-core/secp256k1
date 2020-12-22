with (import <nixpkgs> {}).pkgsi686Linux;
mkShell {
   buildInputs = [
       bash file pkgconfig autoconf automake libtool gmp valgrind clang gcc
   ];
   shellHook = ''
       echo Running nix-shell with nixpkgs version: $(nix eval --raw nixpkgs.lib.version)
   '';
}
