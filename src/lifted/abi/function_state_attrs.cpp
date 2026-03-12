#include "function_state_attrs.hpp"

#include <llvm/Support/Error.h>

namespace lifted::abi
{

namespace
{
    constexpr llvm::StringLiteral kStateFormAttr = "lifted.state_form";
    constexpr llvm::StringLiteral kAnnotationIdAttr = "lifted.annotation_id";

    llvm::Error make_attr_error(const llvm::Function &F, llvm::StringRef message)
    {
        return llvm::make_error<llvm::StringError>(
            "function '" + F.getName().str() + "': " + message.str(),
            llvm::inconvertibleErrorCode());
    }

    llvm::Attribute get_string_attr(const llvm::Function &F, llvm::StringRef name)
    {
        return F.getFnAttribute(name);
    }
} // namespace

    llvm::StringRef to_string(state_form_t form)
    {
        switch (form)
        {
        case state_form_t::folded:
            return "folded";
        case state_form_t::unfolded:
            return "unfolded";
        }
        llvm_unreachable("unknown state_form_t");
    }

    bool has_state_form(const llvm::Function &F)
    {
        return get_string_attr(F, kStateFormAttr).isStringAttribute();
    }

    llvm::Expected<state_form_t> get_state_form(const llvm::Function &F)
    {
        auto attr = get_string_attr(F, kStateFormAttr);
        if (!attr.isStringAttribute())
            return make_attr_error(F, "missing lifted.state_form attribute");

        llvm::StringRef value = attr.getValueAsString();
        if (value == "folded")
            return state_form_t::folded;
        if (value == "unfolded")
            return state_form_t::unfolded;

        return make_attr_error(F, std::string("invalid lifted.state_form value '") + value.str() + "'");
    }

    llvm::Error set_state_form(llvm::Function &F, state_form_t form)
    {
        F.addFnAttr(kStateFormAttr, to_string(form));
        return llvm::Error::success();
    }

    bool has_annotation_id_attr(const llvm::Function &F)
    {
        return get_string_attr(F, kAnnotationIdAttr).isStringAttribute();
    }

    llvm::Expected<annotation_id_t> get_annotation_id(const llvm::Function &F)
    {
        auto attr = get_string_attr(F, kAnnotationIdAttr);
        if (!attr.isStringAttribute())
            return make_attr_error(F, "missing lifted.annotation_id attribute");

        annotation_id_t annotation_id;
        if (attr.getValueAsString().getAsInteger(10, annotation_id.value))
            return make_attr_error(F, std::string("invalid lifted.annotation_id value '") +
                                      attr.getValueAsString().str() + "'");
        if (!annotation_id.valid())
            return make_attr_error(F, "lifted.annotation_id must not be INVALID_ANNOTATION_ID");

        return annotation_id;
    }

    llvm::Error set_annotation_id(llvm::Function &F, annotation_id_t annotation_id)
    {
        if (!annotation_id.valid())
            return make_attr_error(F, "cannot assign INVALID_ANNOTATION_ID");
        F.addFnAttr(kAnnotationIdAttr, std::to_string(annotation_id.value));
        return llvm::Error::success();
    }

    bool has_lifted_state_attrs(const llvm::Function &F)
    {
        return has_state_form(F) && has_annotation_id_attr(F);
    }

    llvm::Error require_lifted_state_attrs(const llvm::Function &F)
    {
        if (auto form_or = get_state_form(F); !form_or)
            return form_or.takeError();
        if (auto annotation_or = get_annotation_id(F); !annotation_or)
            return annotation_or.takeError();
        return llvm::Error::success();
    }

    void copy_lifted_state_attrs(const llvm::Function &src, llvm::Function &dst)
    {
        auto form_attr = get_string_attr(src, kStateFormAttr);
        if (form_attr.isStringAttribute())
            dst.addFnAttr(kStateFormAttr, form_attr.getValueAsString());
        else
            dst.removeFnAttr(kStateFormAttr);

        auto annotation_attr = get_string_attr(src, kAnnotationIdAttr);
        if (annotation_attr.isStringAttribute())
            dst.addFnAttr(kAnnotationIdAttr, annotation_attr.getValueAsString());
        else
            dst.removeFnAttr(kAnnotationIdAttr);
    }

    bool is_state_attr_candidate(const llvm::Function &F)
    {
        if (F.getName().starts_with("__extract_") || F.getName().starts_with("__store_"))
            return false;
        return has_lifted_state_attrs(F);
    }

} // namespace lifted::abi
