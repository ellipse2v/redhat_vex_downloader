
import sys
from pathlib import Path
sys.path.insert(0, '.')
from vex_statistics import VEXAnalyzer

# Use test file if no arguments provided
if len(sys.argv) == 1:
    test_file = Path(__file__).parent / "test_vex.json"
    if test_file.exists():
        print(f'Analyzing test file: {test_file}')
        analyzer = VEXAnalyzer(test_file.parent)
        analyzer.analyze_file(test_file)
        stats = analyzer.stats_by_version
    else:
        print('No test file found and no arguments provided')
        sys.exit(1)
else:
    analyzer = VEXAnalyzer(Path(sys.argv[1]).parent)
    for file_path in sys.argv[1:]:
        print(f'Analyzing {file_path}')
        analyzer.analyze_file(Path(file_path))
    stats = analyzer.stats_by_version

# Print summary instead of saving
print('Analysis complete!')
print(f'Found statistics for RHEL versions: {list(stats.keys())}')
for version, version_stats in stats.items():
    print(f'  {version}: {version_stats.overall.get("total", 0)} total entries')
