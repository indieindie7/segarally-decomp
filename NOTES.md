# Sega Rally Championship (Sega Saturn, AM3 / Sega) decompile notes
Research only, non-commercial. Never publish game files, bins, decompiles or the Ghidra db. No leaked source.
No rebuildable/matching C. User 10-13: "ok lets now go for sega rally please". Same pipeline as manxtt-decomp and powerdrift-decomp.

## Setup (10-13)
- Source: the user's own Sega Rally Championship Plus (USA) Saturn disc image.
- saturn/image/track01.bin (38690400 bytes) + srally.cue. Scorcher tools/isoextract.py track01.bin ../cd 2352 -> saturn/cd/ 598 files.
- IP.BIN: MK-81215 V1.001 1997-05-01, "SEGA RALLY CHAMPIONSHIP PLUS", area U, first read 0x06010000.
- cd/0 (435296) = the Planetweb NetLink browser (HTML strings, www.planetweb.net): third-party, NOT the game; skip.
- cd/RALLY/0RALLY.DAT (266548) = the game main program (SH-2 code at offset 0, references CR*/PR*/BG*/AD*/CGDATA*.DAT, PRGDATA.DAT).
- RALLY/*.MAD = load lists: 16-byte entries {dest addr, size, 0, 0}? (e.g. SELECT.MAD 06050000 / 0002abe0, then 00200000 / 000210d8).
  PRGDATA.DAT (237568) names SD*.DAT sound files and replay/DJ voice files; header word 060cb000.
- 4 courses: DESERT, FOREST, MOUNT(ain), LAKE (+ 2P variants); cars CELICA, LANCIA, STRATOS.
- Import (10-13): ghidra/srrun.sh -import 0RALLY.bin (base 0x06009000) + FindSh2FunctionsMem -> 1420 fn (ExportFuncInfo). tools/srptrs.py (base 06009000) -> ptrcode.txt 1468 lines, 292 starting 2fx6/4f22/7ffx (ptrsel.txt) -> CreateAt 282 ok / 6 failed -> 1729 fn, 4547 calls, 320 string refs (funcinfo_0.tsv). Scripts from Amok/ghidra/scripts via SP=.
- Libraries (10-13): strings "GFS_SBL Version 2.12 1996-12-04", "SYS Version 2.20 1996-08-06", "BUP Version 1.21 1996-08-06"; no SGL. Few frame pointers (6ef3 x46) = Hitachi SHC, not GCC. Refs: PowerDrift GFS_SGL 2.14 + BUP 1.25; ManxTT GFS_SBL 2.10; SonicR SLGFS_SBL 2.10.
- Decider step 1 = tools/libmatch.py (refs in tools/refs.txt: powerdrift, manxtt, sonicr, scorcher LORT, cyberspeedway AUTOEXEC/MENU/MAP1_1). Tiers: body (masked hash), fuzzy (rarity-weighted constant/immediate overlap, --fuzzy T), call (spread via same-position code pointers).
  Blind test on PowerDrift Saturn (--skip powerdrift, --fuzzy 0.55): 253/1049 named; same prefix body 79/98, call 49/81, fuzzy 37/74; most misses = same meaning, other agents' style (cdfs_ vs cdc_). Eval rows: ghidra/lm_pdtest.txt.eval.
  Sega Rally: strict bodies only 10 (SBL is compiled per game -> bytes differ); with --fuzzy 0.55: 156/1729 (body 10, fuzzy 83, call 63) -> ghidra/lm_0.txt. Prefixes cdc 51, gfs 45, gfstrn 16, cd 11.
- Decider step 2 = tools/rules.py -> ghidra/rules_0.txt 17 names (stub 8, wraps 9) + ghidra/hints_0.txt 1548 hint lines (hw blocks, strings, named callees). lm_0 + rules_0 -> ghidra/hand_0.txt 173 lines; ApplyNames + re-dump.
- Step 3 prompt ghidra/naming/n1_prompt_sr.txt (from ManxTT n1_prompt_mx.txt); tools/injecthints.py puts hints into the dump before tools/slice.py.
- Step 3 round 1 (10-13): ApplyNames 173 -> re-dump decomp_0.c (1542 FUN_ left). injecthints -> naming/decomp_hint.c (353 hints), slice.py 10 -> naming/s1..s10.c (175/54/131/205/105/141/187/184/151/209 fn); 10 Sonnet agents -> naming/h1..h10.txt returned 1542 lines (all slices covered, 0 bad lines).
- Round 1 merged (10-13): hand_0.txt 1715 lines (173 decider + 1542 Sonnet), 959 provisional, 2 duplicate names given _2. Backups naming/hand_0_dec.bak (decider only), naming/hand_0_r1.bak. ApplyNames 1715 -> funcinfo_0.tsv 1729 fn, 0 FUN_. Dump -> ghidra/decomp_1.c. Top prefixes: menu 317, vdp2 150, gfs 117, sgl 101, car 87, cdc 74, math 60, cd 60, obj 58, scene 55, snd 45, stub 42.
- Round 2 to-do: the 101 sgl_ names are wrong (the game has no SGL; they are SBL/own code), unify snd_/sound_ prefixes, plus all provisional + _2 names.
- Round 2 (10-13): naming/prov_list.txt 955 (provisional + sgl_ + _N), tools/provctx.py patched (base 0x06009000, image saturn/cd/RALLY/0RALLY.DAT), decomp_0.c = round-1 dump (old one kept as decomp_0_r0.c); naming/r2_1..r2_20.txt + prompt_r2.txt -> 20 Sonnet agents -> naming/v2_1..v2_20.txt, all 955 verdicts back.
- Round 2 applied (10-13): tools/srapply2.py (new; srprovapply only touched "provisional" lines and broke swaps) -> confirmed 519, renamed 333, unsure 103. 18 sound_ -> snd_ by sed. hand_0.txt 1715 lines, 118 provisional, 0 sgl_/sound_, 19 names ending _N, 0 dup names. Backup naming/hand_0_r2.bak (before round 2). ApplyNames 1715 -> funcinfo_0.tsv 0 FUN_. Top prefixes: menu 321, vdp2 145, gfs 116, car 87, vdp1 81, cdc 75, math 72, obj 61, cd 59, scene 57, snd 66.
- Next: round 3 (118 provisional + 19 _N) by hand or one more Sonnet pass, CsDumpAll -> decomp_2.c, then README + repo segarally-decomp.
- Round 3 (10-13): naming/prov3_list.txt 133 (provisional + _N) -> r3_1..4.txt, prompt_r3.txt (name mechanics, UNSURE only with no body) -> 4 Sonnet agents -> naming/v3_1..4.txt (running), then tools/srapply2.py.
- Round 3 applied (10-13): v3_1..4 = 133 verdicts (confirmed 73, renamed 57, unsure 3); backup naming/hand_0_r3.bak. ApplyNames 1715, funcinfo_0.tsv 1729 functions, 0 FUN_, 0 dup names. Left: 3 provisional + 1 more stub = false data fragments (stub_06024bef, stub_06029255, stub_0602db1a, stub_06031606), kept and noted. math_*16_16 = 16.16 fixed point, not _N copies. Top prefixes: menu 321, vdp2 145, gfs 116, car 86, vdp1 82, cdc 75, math 74, snd 64, obj 63, cd 59, scene 56, game 37, race 35, bup 34. Dump -> ghidra/decomp_2.c.
- Next: README + public repo segarally-decomp (names, tools, notes only; scrub like powerdrift).
