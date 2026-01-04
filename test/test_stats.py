
import sys
from pathlib import Path
sys.path.insert(0, '.')
from vex_statistics import analyze_vex_file, save_index

stats = {}

# Use test file if no arguments provided
if len(sys.argv) == 1:
    test_file = Path(__file__).parent / "test_vex.json"
    if test_file.exists():
        print(f'Analyzing test file: {test_file}')
        analyze_vex_file(str(test_file), stats)
    else:
        print('No test file found and no arguments provided')
        sys.exit(1)
else:
    for file_path in sys.argv[1:]:
        print(f'Analyzing {file_path}')
        analyze_vex_file(file_path, stats)

# Save index in test directory
save_index(stats, Path(__file__).parent / "test_stats_index.json")
print('Analysis complete!')
