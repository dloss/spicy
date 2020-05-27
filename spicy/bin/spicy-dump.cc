// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <getopt.h>
#include <iostream>

#include <hilti/hilti.h>
#include <spicy/spicy.h>

#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>

using spicy::rt::fmt;

static struct option long_driver_options[] = {{"abort-on-exceptions", required_argument, nullptr, 'A'},
                                              {"compiler-debug", required_argument, nullptr, 'D'},
                                              {"debug", no_argument, nullptr, 'd'},
                                              {"debug-addl", required_argument, nullptr, 'X'},
                                              {"file", required_argument, nullptr, 'f'},
                                              {"help", no_argument, nullptr, 'h'},
                                              {"library-path", required_argument, nullptr, 'L'},
                                              {"list-parsers", no_argument, nullptr, 'l'},
                                              {"optimize", no_argument, nullptr, 'O'},
                                              {"parser", required_argument, nullptr, 'p'},
                                              {"report-times", required_argument, nullptr, 'R'},
                                              {"show-backtraces", required_argument, nullptr, 'B'},
                                              {"skip-dependencies", no_argument, nullptr, 'S'},
                                              {"version", no_argument, nullptr, 'v'},
                                              {nullptr, 0, nullptr, 0}};

static void fatalError(const std::string& msg) {
    hilti::logger().error(fmt("spicy-dump: %s", msg));
    exit(1);
}

class SpicyDump : public hilti::Driver, public spicy::rt::Driver {
public:
    SpicyDump(const std::string_view& argv0 = "") : hilti::Driver("spicy-dump", argv0) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void parseOptions(int argc, char** argv);
    void usage();

    bool opt_list_parsers = false;
    int opt_increment = 0;
    std::string opt_file = "/dev/stdin";
    std::string opt_parser;

private:
    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

void SpicyDump::usage() {
    auto exts = util::join(hilti::plugin::registry().supportedExtensions(), ", ");

    std::cerr
        << "Usage: cat <data> | spicy-dump [options] <inputs> ...\n"
           "\n"
           "Options:\n"
           "\n"
           "  -d | --debug                    Include debug instrumentation into generated code.\n"
           "  -f | --file <path>              Read input from <path> instead of stdin.\n"
           "  -l | --list-parsers             List available parsers and exit.\n"
           "  -p | --parser <name>            Use parser <name> to process input. Only neeeded if more than one parser "
           "is available.\n"
           "  -v | --version                  Print version information.\n"
           "  -A | --abort-on-exceptions      When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces          Include backtraces when reporting unhandled exceptions.\n"
           "  -D | --compiler-debug <streams> Activate compile-time debugging output for given debug streams "
           "(comma-separated; 'help' for list).\n"
           "  -L | --library-path <path>      Add path to list of directories to search when importing modules.\n"
           "  -O | --optimize                 Build optimized release version of generated code.\n"
           "  -R | --report-times             Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies        Do not automatically compile dependencies during JIT.\n"
           "  -X | --debug-addl <addl>        Implies -d and adds selected additional instrumentation "
           "(comma-separated; see 'help' for list).\n"
           "\n"
           "Environment variables:\n"
           "\n"
           "  SPICY_PATH                      Colon-separated list of directories to search for modules. In contrast "
           "to --library-paths using this flag overwrites builtin paths.\n"
           "\n"
           "Inputs can be "
        << exts
        << ", *.spicy *.hlt *.hlto.\n"
           "\n";
}

/** TODO: Can we factor out optiong handling to driver? */
void SpicyDump::parseOptions(int argc, char** argv) {
    hilti::driver::Options driver_options;
    hilti::Options compiler_options;

    driver_options.execute_code = true;
    driver_options.include_linker = true;
    driver_options.logger = std::make_unique<hilti::Logger>();

    while ( true ) {
        int c = getopt_long(argc, argv, "ABD:f:hdX:OVlp:SRL:", long_driver_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': driver_options.abort_on_exceptions = true; break;

            case 'B': driver_options.show_backtraces = true; break;

            case 'd': {
                compiler_options.debug = true;
                break;
            }

            case 'f': {
                opt_file = optarg;
                break;
            }

            case 'X': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Additional debug instrumentation:\n";
                    std::cerr << "   flow:     log function calls to debug stream \"hilti-flow\"\n";
                    std::cerr << "   location: log statements to debug stream \"hilti-trace\"\n";
                    std::cerr << "   trace:    track current source code location for error reporting\n";
                    std::cerr << "\n";
                    exit(0);
                }

                compiler_options.debug = true;

                if ( auto r = compiler_options.parseDebugAddl(arg); ! r )
                    fatalError(r.error());

                break;
            }

            case 'D': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Debug streams:\n";

                    for ( const auto& s : hilti::logging::DebugStream::all() )
                        std::cerr << "  " << s << "\n";

                    std::cerr << "\n";
                    exit(0);
                }

                for ( const auto& s : util::split(arg, ",") ) {
                    if ( ! driver_options.logger->debugEnable(s) )
                        fatalError(fmt("unknown debug stream '%s', use 'help' for list", arg));
                }

                break;
            }

            case 'l': opt_list_parsers = true; break;

            case 'p': opt_parser = optarg; break;

            case 'O': compiler_options.optimize = true; break;

            case 'R': driver_options.report_times = true; break;

            case 'S': driver_options.skip_dependencies = true; break;

            case 'v': std::cerr << "spicy-dump v" << hilti::configuration().version_string_long << std::endl; exit(0);

            case 'h': usage(); exit(0);

            case 'L': compiler_options.library_paths.emplace_back(optarg); break;

            default: usage(); fatalError(fmt("option %c not supported", c));
        }
    }

    setCompilerOptions(compiler_options);
    setDriverOptions(std::move(driver_options));

    initialize();

    while ( optind < argc ) {
        if ( auto rc = addInput(argv[optind++]); ! rc )
            fatalError(rc.error().description());
    }
}

/** TODO: Move to driver. */
hilti::rt::Result<spicy::rt::ParsedUnit> processInput(const spicy::rt::Parser& parser, std::istream& in) {
    char buffer[4096];
    hilti::rt::ValueReference<hilti::rt::Stream> data;
    std::optional<hilti::rt::Resumable> r;

    spicy::rt::ParsedUnit unit;

    while ( in.good() && ! in.eof() ) {
        in.read(buffer, sizeof(buffer));

        if ( auto n = in.gcount() )
            data->append(hilti::rt::Bytes(buffer, n));

        if ( in.peek() == EOF )
            data->freeze();

        if ( ! r )
            r = parser.parse3(unit, data, {});
        else
            r->resume();

        if ( *r )
            break;
    }

    return std::move(unit);
}

/** Print ASCII representation of parsed unit. */
struct AsciiPrinter {
    void print(const void* ptr, const hilti::rt::TypeInfo* ti) { Visitor(*this, ptr, ti); }

    int level = 0;

    struct Visitor {
        // TODO: Would be nicer to have the visitors at the top-level, but
        // would there be a way then to make the current `ptr`/`ti`
        // available to them? (Short of keeping them in member variables
        // updated each time).
        Visitor(AsciiPrinter& printer, const void* ptr, const hilti::rt::TypeInfo* ti)
            : printer(printer), ptr(ptr), ti(ti) {
            std::visit(*this, ti->type);
        }

        AsciiPrinter& printer;
        const void* ptr;
        const hilti::rt::TypeInfo* ti;

        std::string indent() { return std::string(printer.level * 2, ' '); }
        void print(const void* ptr, const hilti::rt::TypeInfo* ti) { Visitor(printer, ptr, ti); }

        void operator()(const hilti::rt::type_info::Bytes& x) { std::cout << x.get(ptr); }

        void operator()(const hilti::rt::type_info::SignedInteger<int8_t>& x) {
            std::cout << static_cast<int16_t>(x.get(ptr));
        }
        void operator()(const hilti::rt::type_info::SignedInteger<int16_t>& x) { std::cout << x.get(ptr); }
        void operator()(const hilti::rt::type_info::SignedInteger<int32_t>& x) { std::cout << x.get(ptr); }
        void operator()(const hilti::rt::type_info::SignedInteger<int64_t>& x) { std::cout << x.get(ptr); }
        void operator()(const hilti::rt::type_info::String& x) {}
        void operator()(const hilti::rt::type_info::ValueReference& x) {
            auto e = x.element(ptr);
            print(e.first, e.second);
        }
        void operator()(const hilti::rt::type_info::UnsignedInteger<uint8_t>& x) {
            std::cout << static_cast<uint16_t>(x.get(ptr));
        }
        void operator()(const hilti::rt::type_info::UnsignedInteger<uint16_t>& x) { std::cout << x.get(ptr); }
        void operator()(const hilti::rt::type_info::UnsignedInteger<uint32_t>& x) { std::cout << x.get(ptr); }
        void operator()(const hilti::rt::type_info::UnsignedInteger<uint64_t>& x) { std::cout << x.get(ptr); }

        void operator()(const hilti::rt::type_info::Struct& x) {
            std::cout << ti->display << '\n';
            ++printer.level;

            for ( const auto& f : x.fields() ) {
                std::cout << indent() << f.name << " = ";
                print(static_cast<const char*>(ptr) + f.offset, f.type);
                std::cout << std::endl;
            }

            --printer.level;
        }
    };
};

int main(int argc, char** argv) {
    SpicyDump driver;

    driver.parseOptions(argc, argv);

    if ( auto x = driver.compile(); ! x )
        // The main error messages have been reported already at this point.
        // The returned error will have some more info about which pass
        // failed in its description, however that's less interesting to the
        // user so we're just reporting a generic message here.
        fatalError("aborting after errors");

    try {
        auto config = hilti::rt::configuration::get();
        config.cout.reset();
        hilti::rt::configuration::set(config);

        if ( auto x = driver.initRuntime(); ! x )
            fatalError(x.error().description());

        if ( driver.opt_list_parsers )
            driver.listParsers(std::cout);

        else {
            auto parser = driver.lookupParser(driver.opt_parser);
            if ( ! parser )
                fatalError(parser.error());

            std::ifstream in(driver.opt_file, std::ios::in | std::ios::binary);

            if ( ! in.is_open() )
                fatalError("cannot open stdin for reading");

            auto unit = processInput(**parser, in);
            if ( ! unit )
                fatalError(unit.error());

            driver.finishRuntime();

            AsciiPrinter().print(unit->pointer(), unit->typeinfo());
        }

    } catch ( const std::exception& e ) {
        std::cerr << util::fmt("[fatal error] terminating with uncaught exception of type %s: %s",
                               util::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    }

    if ( driver.driverOptions().report_times )
        util::timing::summary(std::cerr);

    return 0;
}
