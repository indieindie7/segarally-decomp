# Sega Rally Championship Plus (Sega Saturn) reverse-engineering notes and symbols

Function names, tools and working notes for the main program of **Sega Rally Championship Plus** (Saturn, USA,
1997). The game code is one SH-2 program (`RALLY/0RALLY.DAT`, loaded at `0x06009000`) built with Hitachi SHC and
linked with Sega's SBL libraries (GFS, CDC, SYS, BUP, SCU DMA, VDP1/VDP2, SMPC, SCSP sound). It does not use SGL.
Same method as [powerdrift-decomp](https://github.com/indieindie7/powerdrift-decomp),
[manxtt-decomp](https://github.com/indieindie7/manxtt-decomp) and [sonicr-decomp](https://github.com/indieindie7/sonicr-decomp).
Non-commercial, done for study and preservation. No game data, binaries or decompiled C are in this repository,
and this is not a matching or rebuildable decompilation.

All 1729 functions have a name (1715 hand-file lines; the other 14 are switch-case labels Ghidra split off as functions), 0 `FUN_` left.
Three names stay provisional: they are data fragments that Ghidra decoded as code (`stub_06024bef`, `stub_06029255`,
`stub_0602db1a`).

## How it was named

1. **Decider** (`tools/libmatch.py`, `tools/rules.py`): deterministic matching against already named Saturn games
   (body hash, fuzzy instruction match, call-graph votes; `tools/refs.txt` lists the references), plus rules for
   empty stubs, constant returns and small wrappers. 173 names.
2. **Three review rounds** by language-model agents reading each function's decompile together with its callers
   (`tools/provctx.py` builds the context slices; prompts in `ghidra/naming/`). Verdicts CONFIRM / RENAME / UNSURE were
   applied by address with `tools/srapply2.py`, which frees renamed names first so swaps work.
3. Names come only from what the code does. No leaked source was used.

Largest groups: `menu_` 321, `vdp2_` 145, `gfs_` 116, `car_` 86, `vdp1_` 82, `cdc_` 75, `math_` 74, `snd_` 64,
`obj_` 63, `cd_` 59, `scene_` 56, `game_` 37, `race_` 35, `bup_` 34.

## What is here

| Path | Content |
|---|---|
| `NOTES.md` | the working log: disc layout, load lists, every naming round with counts |
| `ghidra/hand_0.txt` | the names: `0x<addr> func <name> hand <comment>`; `(was X)` marks a rename |
| `ghidra/naming/` | the review prompts for rounds 2 and 3 |
| `ghidra/scripts/` | headless Ghidra scripts: SH-2 function finder, name import, function info export, decompile dump |
| `ghidra/srrun.sh` | headless runner (set `GHIDRA_HEADLESS` and `SR_GHIDRA`) |
| `tools/libmatch.py`, `rules.py`, `injecthints.py` | the decider: cross-game matching, rule names, hints for the review |
| `tools/provctx.py`, `srapply2.py`, `slice.py` | review context builder and verdict applier |
| `tools/findbase.py`, `srptrs.py` | load-address finder and pointer scan |

## Use

Bring your own disc. Extract `RALLY/0RALLY.DAT`, import it into Ghidra as raw SH-2 big-endian at `0x06009000`, run
`FindSh2Functions.java`, then `ApplyNames.java ghidra/hand_0.txt hand`.

## License

The notes, names and tools are released under the license in `LICENSE`. Sega Rally is a trademark of Sega;
this project is not affiliated with or endorsed by Sega.
