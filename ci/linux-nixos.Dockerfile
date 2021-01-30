FROM nixos/nix

COPY ci/shell.nix /tmp
COPY ci/shell-i686.nix /tmp

RUN nix-channel --remove nixpkgs
RUN nix-channel --add https://nixos.org/channels/nixos-20.09 nixpkgs
RUN nix-channel --update

# Run dummy command "true" in the nix-shell just to get the packages prepared.
RUN nix-shell /tmp/shell.nix --command true
RUN nix-shell /tmp/shell-i686.nix --command true
