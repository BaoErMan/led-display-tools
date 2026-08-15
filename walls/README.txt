Per-wall Huidu brightness templates live here, one per wall, each with its
.wall.json fingerprint beside it.

  python provision_wall.py --port COM8 \
      --config "C:\...\HDset\public\recvfile\net_default_new.xml" --name wall_north

Then run the client with:  --hd-template walls/wall_north.bin

example_wall1.bin is from the development rig and is for REFERENCE ONLY. Do not
send it to any other wall: a Huidu brightness command carries that wall's entire
screen configuration (EDID, timings, display geometry), so the wrong template
reconfigures the screen. HdLink.connect() re-probes the wall at startup and
refuses a template whose fingerprint does not match.

HD-Y1 walls additionally need an AUTO-RANGE template (<name>_auto.bin) to steer
their on-card ambient loop - a class-0x02/sub-0x01/target-0x78 block. It is NOT in
HDset's config, so it comes from a capture:

  python led_probe/led_probe_re/hd_bright.py --extract-auto-template change_auto.pcapng \
      --auto-template walls/wall_north_auto.bin

example_wall1_auto.bin is from the development rig - reference only, same warning.

