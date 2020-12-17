import fcntl
import termios
import struct

import support_diagnostics
from support_diagnostics.output import Output

class ReportOutput(Output):
    rows = None
    columns = None

    def static_init():
        pad = "0" * 8
        s = fcntl.ioctl(1, termios.TIOCGWINSZ, pad)
        sz = struct.unpack('hhhh', s)
        ReportOutput.rows = sz[0]
        ReportOutput.columns = sz[1]
        # print("rows: {} columns: {}, xpixels: {}, ypixels: {}". format(*sz))

    def generate(self, analyser_results):
        for analyzer in analyser_results:
            print(support_diagnostics.Colors.format("{header}{padding}".format(header=analyzer.heading,padding=" " * (ReportOutput.columns - len(analyzer.heading))), support_diagnostics.Colors.BLACK_FOREGROUND, support_diagnostics.Colors.GREY_BACKGROUND))
            if analyser_results[analyzer] is not None:
                for analyzer_result in analyser_results[analyzer]:
                    # !!! filter severity
                    if analyzer_result.severity is not None:
                        severity = support_diagnostics.Colors.format(analyzer_result.severity.name, analyzer_result.severity.foreground_color, analyzer_result.severity.background_color) 
                        if severity not in ''.join(analyzer_result.results.values()) and severity not in ''.join(analyzer_result.results.keys()): 
                            print(severity)

                    if 'summary' in analyzer_result.results:
                        if analyzer_result.results['summary'] not in ''.join({k: v for k, v in analyzer_result.results.items() if not k.startswith('summary')}.values()):
                            print(support_diagnostics.Colors.format("{header:<16}{result}".format(header="Summary", result=analyzer_result.results['summary'])))

                    if 'detail' in analyzer_result.results:
                        print(support_diagnostics.Colors.format("{header:<16}{result}".format(header="Detail", result=analyzer_result.results['detail'])))

                    if 'recommendation' in analyzer_result.results:
                        print(support_diagnostics.Colors.format("{header:<16}{result}".format(header="Recommendation", result=analyzer_result.results['recommendation'])))

                    # All other results.
                    for key in analyzer_result.results:
                        if key != 'summary' and key != 'detail' and key != 'recommendation':
                            if key.startswith("\33"):
                                # ANSI screws up formatting for severity.  Adjust padding to align.
                                padding = 5 - (32 - len(key))
                                print(support_diagnostics.Colors.format("{header:<35}{padding}{result}".format(header=key, padding=" " * padding, result=analyzer_result.results[key])))
                            else:
                                print(support_diagnostics.Colors.format("{header:<35}{result}".format(header=key.capitalize(), result=analyzer_result.results[key])))

                    # print()
        print()
        
if ReportOutput.rows is None:
    ReportOutput.static_init()