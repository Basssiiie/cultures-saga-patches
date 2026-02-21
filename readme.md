# Cultures Saga patches

This repository contains various executable patches for Cultures Saga, which are used in projects like the CulturesNation mod.

These include but are not limited to:
- Fix for a freeze when building vehicles with multiple carpenters/builders.
- Fix for a freeze when a soldier tries to attack something outside its hardcoded attack radius, while in the ignorant military mode.
- Fix for a crash when AI tries to build signposts on the map edge.
- Increasing the human limit from 1000 to 5000.
- Increasing the house limit from 400 to 2000.
- Increasing the animal limit from 500 to 2500.
- Increasing the total movables (humans, animals, vehicles) limit from 2000 to 10.000.
- Increasing the mission limit from 150 to 900.
- Increasing the pathfinding limit from 2000 to 10.000.
- Increasing the assistant limit from 20 to 100.
- Make the pathfinder work about 11 times faster, from 2 to 22 simultaneous searches.
- Make the assistant work about 7 times faster, from every 15 seconds to every 2 seconds.
- Allow assistant requests to be increased and decreased by 10 with CTRL-clicking.

Additional credits and thanks goes to [Siguza](https://github.com/Siguza), [Mikulus](https://github.com/Mikulus6), [Tyrannica](https://github.com/ARKAMENTOR) for making these patches possible.

## How to patch

Install dependencies with:
```bash
pip install -r requirements.txt
```

Run the program with:
```bash
python ./main.py <path to exe>
```

If no executable path is submitted, it will request you to input one after launch.

Optionally, add one of the following arguments for further configuration:
| Argument | Shorthand | Description |
|---|---|---|
| `--output <path>` | `-o` | Path including filename of where to save the result. If not provided, it will create a new file in same folder as input. |
| `--force` | `-f` | Patch segments regardless of whether they fail verification. |
| `--verbose` | `-v` | Prints additional logging for each patch attempt. |
