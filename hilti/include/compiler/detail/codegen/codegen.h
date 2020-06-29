// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>

#include <hilti/ast/function.h>
#include <hilti/base/cache.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/unit.h>

namespace hilti {

class Node;
class Unit;

namespace detail {

namespace codegen {
enum class TypeUsage { Storage, CopyParameter, InParameter, InOutParameter, FunctionResult, Ctor, None };

struct CxxTypes {
    std::optional<cxx::Type> base_type;
    std::optional<cxx::Type> storage;
    std::optional<cxx::Type> result;
    std::optional<cxx::Type> param_copy;
    std::optional<cxx::Type> param_in;
    std::optional<cxx::Type> param_inout;
    std::optional<cxx::Type> ctor;
    std::optional<cxx::Expression> default_;
    std::optional<cxx::Expression> type_info;
};

struct CxxTypeInfo {
    bool predefined;
    cxx::Expression reference;
    std::optional<cxx::declaration::Constant> forward;
    std::optional<cxx::declaration::Constant> declaration;
};

} // namespace codegen

/**
 * HILTI's code generator. This is the main internal entry point for
 * generating C++ code from HILTI source code.
 */
class CodeGen {
public:
    CodeGen(std::shared_ptr<Context> context) : _context(std::move(context)) {}

    /** Entry point for code generation. */
    Result<cxx::Unit> compileModule(Node& root, hilti::Unit* hilti_unit,
                                    bool include_implementation); // NOLINT(google-runtime-references)

    /** Entry point for generating additional cross-unit C++ code through HILTI's linker. */
    Result<cxx::Unit> linkUnits(const std::vector<cxx::linker::MetaData>& mds);

    std::shared_ptr<Context> context() const { return _context; }
    const Options& options() const { return _context->options(); }

    // These must be called only while a module is being compiled.
    std::optional<cxx::declaration::Type> typeDeclaration(const hilti::Type& t);
    std::list<cxx::declaration::Type> typeDependencies(const hilti::Type& t);
    cxx::Type compile(const hilti::Type& t, codegen::TypeUsage usage);
    cxx::Expression compile(const hilti::Expression& e, bool lhs = false);
    cxx::Expression compile(const hilti::Ctor& c);
    cxx::Expression compile(const hilti::expression::ResolvedOperator& o, bool lhs = false);
    cxx::Block compile(const hilti::Statement& s, cxx::Block* b = nullptr);
    cxx::declaration::Function compile(const ID& id, type::Function ft, declaration::Linkage linkage,
                                       function::CallingConvention cc = function::CallingConvention::Standard,
                                       const std::optional<AttributeSet>& fattrs = {},
                                       std::optional<cxx::ID> namespace_ = {});
    std::vector<cxx::Expression> compileCallArguments(const std::vector<Expression>& args,
                                                      const std::vector<declaration::Parameter>& params);
    std::optional<cxx::Expression> typeDefaultValue(const hilti::Type& t);

    cxx::Expression typeInfo(const hilti::Type& t);
    void addTypeInfoDefinition(const hilti::Type& t);

    cxx::Expression coerce(const cxx::Expression& e, const Type& src, const Type& dst); // only for supported coercions
    cxx::Expression unpack(const hilti::Type& t, const Expression& data, const std::vector<Expression>& args);
    cxx::Expression unpack(const hilti::Type& t, const cxx::Expression& data, const std::vector<cxx::Expression>& args);
    void addDeclarationFor(const hilti::Type& t) { _need_decls.push_back(t); }

    cxx::Expression addTmp(const std::string& prefix, const cxx::Type& t);
    cxx::Expression addTmp(const std::string& prefix, const cxx::Expression& init);

    cxx::Expression self() const { return _selfs.back(); }
    cxx::Expression dollardollar() const {
        return "__dd";
    } // TODO(robin): We hardcode the currently; need a stack, too?
    void pushSelf(detail::cxx::Expression e) { _selfs.push_back(std::move(e)); }
    void popSelf() { _selfs.pop_back(); }

    auto cxxBlock() const { return ! _cxx_blocks.empty() ? _cxx_blocks.back() : nullptr; }
    void pushCxxBlock(cxx::Block* b) { _cxx_blocks.push_back(b); }
    void popCxxBlock() { _cxx_blocks.pop_back(); }

    void enablePrioritizeTypes() { ++_prioritize_types; }
    void disablePrioritizeTypes() { --_prioritize_types; }
    bool prioritizeTypes() const { return _prioritize_types > 0; }

    cxx::Unit* unit() const;        // will abort if not compiling a module.
    hilti::Unit* hiltiUnit() const; // will abort if not compiling a module.

private:
    const codegen::CxxTypeInfo& _getOrCreateTypeInfo(const hilti::Type& t, bool add_implementation);

    std::unique_ptr<cxx::Unit> _cxx_unit;
    hilti::Unit* _hilti_unit = nullptr;
    std::shared_ptr<Context> _context;
    std::vector<detail::cxx::Expression> _selfs = {"__self"};
    std::vector<detail::cxx::Block*> _cxx_blocks;
    std::vector<detail::cxx::declaration::Local> _tmps;
    std::map<std::string, int> _tmp_counters;
    std::vector<hilti::Type> _need_decls;
    hilti::util::Cache<cxx::ID, codegen::CxxTypes> _cache_types_storage;
    hilti::util::Cache<cxx::ID, codegen::CxxTypeInfo> _cache_type_info;
    hilti::util::Cache<cxx::ID, cxx::declaration::Type> _cache_types_declarations;
    int _prioritize_types = 0;
};

} // namespace detail
} // namespace hilti
