# rite-solver

Opens the Annual Rite's sealed guestbook entries. Each entry is an RSW
time-lock puzzle: the only known way in without the factors of N is to
square 2 modulo N, T times in a row. See `RULES.md` for the exact format.

```sh
cargo build --release                     # needs a C compiler and m4; GMP is built from source

./target/release/rite-solver open 12                          # fetch entry 12 from the site
./target/release/rite-solver open 12 --ledger ledger/2026.json   # or read it from a ledger file
./target/release/rite-solver open --file entry.json           # or from a JSON file of its own
./target/release/rite-solver bench                            # squarings/s here, and the T for each seal
```

Progress is saved to `rite-checkpoints/` (change it with `--dir`) every 30
seconds and on Ctrl-C. Running the same command again resumes, on this
machine or another one. `--yes` skips the prompt; `--quiet` skips the
ceremony and the progress line.

`bench` is how each year's T is chosen: run it on a fast desktop CPU before
the Day and copy its numbers into `src/shared/seals.ts`.
