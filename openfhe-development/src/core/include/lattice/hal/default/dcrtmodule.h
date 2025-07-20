//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Represents integer lattice elements with double-CRT
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTMODULE_H
#define LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTMODULE_H

#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/poly.h"
#include "lattice/hal/dcrtpoly-interface.h"

#include "math/math-hal.h"
#include "math/distrgen.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/parallel.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename VecType>
class DCRTModuleImpl final : public ILElement<DCRTModuleImpl<VecType>, VecType> {
public:
    using Vector                  = VecType;
    using Integer                 = typename VecType::Integer;
    using Params                  = ILDCRTParams<Integer>;
    using PolyType                = PolyImpl<NativeVector>;
    using PolyLargeType           = PolyImpl<VecType>;
    using DCRTPolyType            = DCRTPolyImpl<VecType>;
    using DCRTPolyInterfaceType   = DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl>;
    using DCRTModuleType          = DCRTModuleImpl<VecType>;
    using DCRTModuleInterfaceType = ILElement<DCRTModuleImpl<VecType>, VecType>;
    using Precomputations         = typename DCRTPolyInterfaceType::CRTBasisExtensionPrecomputations;
    using DggType                 = typename DCRTPolyInterfaceType::DggType;
    using DugType                 = typename DCRTPolyInterfaceType::DugType;
    using TugType                 = typename DCRTPolyInterfaceType::TugType;
    using BugType                 = typename DCRTPolyInterfaceType::BugType;

    DCRTModuleImpl() = default;

    DCRTModuleImpl(const std::shared_ptr<Params>& params, const Format format = Format::EVALUATION,
                   bool initializeElementToZero = false, uint32_t moduleRows = 1, uint32_t moduleCols = 1) noexcept
        : m_params{params}, m_format{format}, m_vectors{}, m_moduleRows{moduleRows}, m_moduleCols{moduleCols} {
        m_vectors.reserve(m_moduleRows * m_moduleCols);
        for (usint i = 0; i < m_moduleRows * m_moduleCols; i++) {
            m_vectors.emplace_back(m_params, m_format, initializeElementToZero);
        }
    }

    DCRTModuleImpl(const DggType& dgg, const std::shared_ptr<Params>& dcrtParams, Format format,
                   uint32_t moduleRows = 1, uint32_t moduleCols = 1)
        : m_params{dcrtParams}, m_format{format}, m_moduleRows{moduleRows}, m_moduleCols{moduleCols} {
        m_vectors.reserve(m_moduleRows * m_moduleCols);
        for (usint i = 0; i < m_moduleRows * m_moduleCols; i++) {
            m_vectors.emplace_back(dgg, m_params, m_format);
        }
    }

    DCRTModuleImpl(DugType& dug, const std::shared_ptr<Params>& dcrtParams, Format format, uint32_t moduleRows = 1,
                   uint32_t moduleCols = 1)
        : m_params{dcrtParams}, m_format{format}, m_moduleRows{moduleRows}, m_moduleCols{moduleCols} {
        m_vectors.reserve(m_moduleRows * m_moduleCols);
        for (usint i = 0; i < m_moduleRows * m_moduleCols; i++) {
            m_vectors.emplace_back(dug, m_params, m_format);
        }
    }

    DCRTModuleImpl(const BugType& bug, const std::shared_ptr<Params>& dcrtParams, Format format,
                   uint32_t moduleRows = 1, uint32_t moduleCols = 1)
        : m_params{dcrtParams}, m_format{format}, m_moduleRows{moduleRows}, m_moduleCols{moduleCols} {
        m_vectors.reserve(m_moduleRows * m_moduleCols);
        for (usint i = 0; i < m_moduleRows * m_moduleCols; i++) {
            m_vectors.emplace_back(bug, m_params, m_format);
        }
    }

    DCRTModuleImpl(const TugType& tug, const std::shared_ptr<Params>& dcrtParams, Format format, uint32_t h = 0,
                   uint32_t moduleRows = 1, uint32_t moduleCols = 1)
        : m_params{dcrtParams}, m_format{format}, m_moduleRows{moduleRows}, m_moduleCols{moduleCols} {
        m_vectors.reserve(m_moduleRows * m_moduleCols);
        for (usint i = 0; i < m_moduleRows * m_moduleCols; i++) {
            m_vectors.emplace_back(tug, m_params, m_format, h);
        }
    }

    DCRTModuleImpl(const DCRTPolyType& poly) noexcept
        : m_params{poly.GetParams()}, m_format{poly.GetFormat()}, m_vectors{}, m_moduleRows{1}, m_moduleCols{1} {
        m_vectors.resize(1);
        m_vectors[0] = poly;
    }

    DCRTModuleImpl(const DCRTModuleType& e) noexcept
        : m_params{e.m_params},
          m_format{e.m_format},
          m_vectors{e.m_vectors},
          m_moduleRows{e.m_moduleRows},
          m_moduleCols{e.m_moduleCols} {}
    const DCRTModuleType& operator=(const DCRTModuleType& rhs) override {
        m_params     = rhs.m_params;
        m_format     = rhs.m_format;
        m_vectors    = rhs.m_vectors;
        m_moduleRows = rhs.m_moduleRows;
        m_moduleCols = rhs.m_moduleCols;
        return *this;
    }

    /**
   * @brief Clone the object by making a copy of it and returning the copy
   * @return new Element
   */
    DCRTModuleType Clone() const final {
        return DCRTModuleType(*this);
    }

    /**
 * @brief Clone the object, but have it contain nothing
 * @return new Element
 */
    DCRTModuleType CloneEmpty() const final {
        OPENFHE_THROW("CloneEmpty not implemented");
    }

    /**
 * @brief Clones the element's parameters, leaves vector initialized to 0
 * @return new Element
 */
    DCRTModuleType CloneParametersOnly() const final {
        OPENFHE_THROW("CloneParametersOnly not implemented");
    }

    /**
 * @brief Clones the element with parameters and with noise for the vector
 * @param dgg
 * @param format
 * @return new Element
 */
    DCRTModuleType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const {
        OPENFHE_THROW("CloneWithNoise not implemented");
    };

    // Assignment operators
    /**
 * @brief Assignment operator that copies elements.
 * @param rhs
 */
    const DCRTModuleType& operator=(DCRTModuleType&& rhs) override {
        m_params     = std::move(rhs.m_params);
        m_format     = std::move(rhs.m_format);
        m_vectors    = std::move(rhs.m_vectors);
        m_moduleRows = std::move(rhs.m_moduleRows);
        m_moduleCols = std::move(rhs.m_moduleCols);
        return *this;
    }
    /**
 * @brief Assignment operator that copies elements.
 * @param rhs
 */
    const DCRTModuleType& operator=(std::initializer_list<uint64_t> rhs) override {
        OPENFHE_THROW("operator= not implemented");
    }

    // GETTERS
    /**
 * @brief Get format of the element
 *
 * @return Format is either COEFFICIENT or EVALUATION
 */
    Format GetFormat() const {
        return m_format;
    }

    /**
 * @brief Get the length of the element.
 *
 * @return length
 */
    usint GetLength() const {
        return m_moduleRows;
    }

    usint GetModuleRows() const {
        return m_moduleRows;
    }

    usint GetModuleCols() const {
        return m_moduleCols;
    }

    /**
 * @brief Get modulus of the element
 *
 * @return the modulus.
 */
    const Integer& GetModulus() const {
        return m_params->GetModulus();
    };
    /**
 * @brief Get the cyclotomic order
 *
 * @return order
 */
    usint GetCyclotomicOrder() const {
        return m_params->GetCyclotomicOrder();
    }

    const VecType& GetValues() const {
        OPENFHE_THROW("GetValues not implemented for DCRTModule");
    }

    const usint GetRingDimension() const {
        return m_params->GetRingDimension();
    }

    /**
     * @brief Unary negation on a lattice
     * @return -lattice
     */
    DCRTModuleType operator-() const {
        return DCRTModuleType(m_params, m_format, true, m_moduleRows, m_moduleCols) -= *this;
    }

    DCRTModuleType Negate() const {
        return DCRTModuleType(m_params, m_format, true, m_moduleRows, m_moduleCols) -= *this;
    }

    /**
 * @brief Scalar addition - add an element
 *
 * @param &element is the element to add entry-wise.
 * @return is the return of the addition operation.
 */
    DCRTModuleType Plus(const Integer& element) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] + element;
        }
        return tmp;
    }

    /**
 * @brief Scalar subtraction - subtract an element frp, all entries.
 *
 * @param &element is the element to subtract entry-wise.
 * @return is the return value of the minus operation.
 */
    DCRTModuleType Minus(const Integer& element) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] - element;
        }
        return tmp;
    }

    /**
 * @brief Scalar multiplication - multiply all entries.
 *
 * @param &element is the element to multiply entry-wise.
 * @return is the return value of the times operation.
 */
    DCRTModuleType Times(const Integer& element) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] * element;
        }
        return tmp;
    }

    /**
 * @brief Scalar multiplication - multiply all entries.
 *
 * @param &element is the element to multiply entry-wise.
 * @return is the return value of the times operation.
 */
    DCRTModuleType Times(const std::vector<Integer>& crtElement) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] * crtElement;
        }
        return tmp;
    }

    /**
 * @brief Scalar multiplication - mulltiply by a signed integer
 *
 * @param &element is the element to multiply entry-wise.
 * @return is the return value of the times operation.
 */
    DCRTModuleType Times(NativeInteger::SignedNativeInt element) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] * element;
        }
        return tmp;
    }

    /**
 * @brief Performs an addition operation and returns the result.
 *
 * @param &element is the element to add with.
 * @return is the result of the addition.
 */
    DCRTModuleType Plus(const DCRTModuleType& element) const {
        if (m_moduleCols != element.m_moduleCols || m_moduleRows != element.m_moduleRows) {
            OPENFHE_THROW("Size mismatch");
        }
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] + element.m_vectors[i];
        }
        return tmp;
    }

    /**
 * @brief Performs a subtraction operation and returns the result.
 *
 * @param &element is the element to subtract with.
 * @return is the result of the subtraction.
 */
    DCRTModuleType Minus(const DCRTModuleType& element) const {
        if (m_moduleCols != element.m_moduleCols || m_moduleRows != element.m_moduleRows) {
            OPENFHE_THROW("Size mismatch");
        }
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i] - element.m_vectors[i];
        }
        return tmp;
    }

    /**
 * @brief Performs a multiplication operation and returns the result.
 *
 * @param &element is the element to multiply with.
 * @return is the result of the multiplication.
 */
    DCRTModuleType Times(const DCRTModuleType& element) const {
        if (m_moduleRows == 1 && m_moduleCols == 1) {
            DCRTModuleType tmp(m_params, m_format, false, element.m_moduleRows, element.m_moduleCols);
            for (usint i = 0; i < element.m_vectors.size(); i++) {
                tmp.m_vectors[i] = m_vectors[0] * element.m_vectors[i];
            }
            return tmp;
        }
        else if (element.m_moduleRows == 1 && element.m_moduleCols == 1) {
            DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
            for (usint i = 0; i < m_vectors.size(); i++) {
                tmp.m_vectors[i] = m_vectors[i] * element.m_vectors[0];
            }
            return tmp;
        }

        if (m_moduleCols != element.m_moduleRows) {
            OPENFHE_THROW("Times size mismatch");
        }

        DCRTModuleType tmp(m_params, m_format, true, m_moduleRows, element.m_moduleCols);
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(tmp.m_moduleRows))
        for (usint row = 0; row < tmp.m_moduleRows; row++) {
            for (usint col = 0; col < tmp.m_moduleCols; col++) {
                for (usint i = 0; i < m_moduleCols; i++) {
                    tmp.m_vectors[row * tmp.m_moduleCols + col] +=
                        m_vectors[row * m_moduleCols + i] * element.m_vectors[i * element.m_moduleCols + col];
                }
            }
        }
        return tmp;
    }

    DCRTModuleType HadamardProduct(const DCRTModuleType& element) const {
        if (m_moduleCols != element.m_moduleCols || m_moduleRows != element.m_moduleRows) {
            OPENFHE_THROW("HadamardProduct size mismatch");
        }
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        for (usint i = 0; i < m_vectors.size(); i++) {
            tmp.m_vectors[i] = m_vectors[i] * element.m_vectors[i];
        }
        return tmp;
    }

    DCRTModuleType LowerTriangleProduct(const DCRTModuleType& element) const {
        if ((m_moduleCols != 1 && m_moduleRows != 1) || m_moduleRows != element.m_moduleRows ||
            m_moduleCols != element.m_moduleCols) {
            OPENFHE_THROW("LowerTriangleProduct size mismatch");
        }
        int rows = m_moduleRows * (m_moduleRows - 1) / 2;
        int cols = 1;
        if (m_moduleRows == 1) {
            rows = 1;
            cols = m_moduleCols * (m_moduleCols - 1) / 2;
        }
        DCRTModuleType tmp(m_params, m_format, false, rows, cols);
        int k = 0;
        for (usint i = 0; i < m_vectors.size(); i++) {
            for (usint j = i + 1; j < m_vectors.size(); j++) {
                tmp.m_vectors[k++] = m_vectors[i] * element.m_vectors[j];
            }
        }
        return tmp;
    }

    // overloaded op= operators
    /**
 * @brief Performs += operation with a Integer and returns the result.
 *
 * @param &element is the element to add
 * @return is the result of the addition.
 */
    const DCRTModuleType& operator+=(const Integer& element) {
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i] += element;
        }
        return *this;
    }

    /**
 * @brief Performs -= operation with a Integer and returns the result.
 *
 * @param &element is the element to subtract
 * @return is the result of the addition.
 */
    const DCRTModuleType& operator-=(const Integer& element) {
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i] -= element;
        }
        return *this;
    }

    /**
 * @brief Performs *= operation with a Integer and returns the result.
 *
 * @param &element is the element to multiply by
 * @return is the result of the multiplication.
 */
    const DCRTModuleType& operator*=(const Integer& element) {
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i] *= element;
        }
        return *this;
    }

    /**
 * @brief Performs an addition operation and returns the result.
 *
 * @param &element is the element to add
 * @return is the result of the addition.
 */
    const DCRTModuleType& operator+=(const DCRTModuleType& element) {
        if (m_moduleCols != element.m_moduleCols || m_moduleRows != element.m_moduleRows) {
            OPENFHE_THROW("Size mismatch");
        }
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i] += element.m_vectors[i];
        }
        return *this;
    }

    /**
 * @brief Performs an subtraction operation and returns the result.
 *
 * @param &element is the element to subtract
 * @return is the result of the addition.
 */
    const DCRTModuleType& operator-=(const DCRTModuleType& element) {
        if (m_moduleCols != element.m_moduleCols || m_moduleRows != element.m_moduleRows) {
            OPENFHE_THROW("Size mismatch");
        }
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i] -= element.m_vectors[i];
        }
        return *this;
    }

    /**
 * @brief Performs an multiplication operation and returns the result.
 *
 * @param &element is the element to multiply by
 * @return is the result of the multiplication.
 */
    const DCRTModuleType& operator*=(const DCRTModuleType& element) {
        OPENFHE_THROW("operator*= not implemented");
    }

    /**
 * @brief Equality operator.  Compares values of element to be compared to.
 * @param element the element to compare to.
 */
    bool operator==(const DCRTModuleType& rhs) const {
        return ((m_format == rhs.m_format) && (m_params->GetCyclotomicOrder() == rhs.m_params->GetCyclotomicOrder()) &&
                (m_params->GetModulus() == rhs.m_params->GetModulus()) && (m_vectors.size() == rhs.m_vectors.size()) &&
                (m_vectors == rhs.m_vectors) && (m_moduleCols == rhs.m_moduleCols));
    }

    /**
 * @brief Inequality operator.  Compares values of element to be compared to.
 * @param element the element to compare to.
 */
    inline bool operator!=(const DCRTModuleType& element) const {
        return !(*this == element);
    }

    /**
 * @brief Adds one to every entry of the Element, in place
 */
    void AddILElementOne() {
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            m_vectors[i].AddILElementOne();
        }
    }

    void DropLastElement() {
        for (auto& v : m_vectors)
            v.DropLastElement();
        Params* newP = new Params(*m_params);
        newP->PopLastParam();
        m_params.reset(newP);
    }

    void DropLastElements(size_t i) {
        for (auto& v : m_vectors)
            v.DropLastElements(i);
        Params* newP = new Params(*m_params);
        for (size_t j = 0; j < i; ++j)
            newP->PopLastParam();
        m_params.reset(newP);
    }

    // used for CKKS rescaling
    void DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                 const std::vector<NativeInteger>& qlInvModq) {
        for (auto& v : m_vectors)
            v.DropLastElementAndScale(QlQlInvModqlDivqlModq, qlInvModq);
        Params* newP = new Params(*m_params);
        newP->PopLastParam();
        m_params.reset(newP);
    }

    usint GetNumOfElements() const {
        return m_vectors[0].GetNumOfElements();
    }

    /**
 * @brief Performs an automorphism transform operation and returns the result.
 *
 * @param &i is the element to perform the automorphism transform with.
 * @return is the result of the automorphism transform.
 */
    DCRTModuleType AutomorphismTransform(uint32_t i) const {
        OPENFHE_THROW("AutomorphismTransform not implemented");
    }

    /**
 * @brief Performs an automorphism transform operation using precomputed bit
 * reversal indices.
 *
 * @param &i is the element to perform the automorphism transform with.
 * @param &vec a vector with precomputed indices
 * @return is the result of the automorphism transform.
 */
    DCRTModuleType AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const {
        OPENFHE_THROW("AutomorphismTransform not implemented");
    }

    /**
 * @brief Transpose the ring element using the automorphism operation
 *
 * @return is the result of the transposition.
 */
    DCRTModuleType Transpose() const {
        OPENFHE_THROW("Transpose not implemented");
    }

    /**
 * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base}
 * \rfloor} {(base^i u_i)} \f$ and return the vector of \f$ \left\{u_0,
 * u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil
 * {\log q/base} \rceil}} \f$; This is used as a subroutine in the
 * relinearization procedure.
 *
 * @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
 * @param evalModeAnswer - if true, convert the resultant polynomials to
 * evaluation mode
 * @result is the pointer where the base decomposition vector is stored
 */
    std::vector<DCRTModuleType> BaseDecompose(usint baseBits, bool evalModeAnswer) const {
        OPENFHE_THROW("BaseDecompose not implemented");
    }

    /**
 * @brief Scalar division followed by rounding operation - operation on all
 * entries.
 *
 * @param &q is the element to divide entry-wise.
 * @return is the return value of the divide, followed by rounding operation.
 */
    DCRTModuleType DivideAndRound(const Integer& q) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i].DivideAndRound(q);
        }
        return tmp;
    }

    DCRTModuleType ApproxModDown(
        const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
        const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
        const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
        const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
        const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
        const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] =
                m_vectors[i].ApproxModDown(paramsQ, paramsP, PInvModq, PInvModqPrecon, PHatInvModp, PHatInvModpPrecon,
                                           PHatModq, modqBarrettMu, tInvModp, tInvModpPrecon, t, tModqPrecon);
        }
        return tmp;
    }

    /**
 * @brief Determines if inverse exists
 *
 * @return true if there exists a multiplicative inverse.
 */
    bool InverseExists() const {
        OPENFHE_THROW("InverseExists not implemented");
    }

    /**
 * @brief Returns the infinity norm, basically the largest value in the ring
 * element.
 *
 * @return the largest value in the ring element.
 */
    double Norm() const {
        OPENFHE_THROW("Norm not implemented");
    }

    /**
 * @brief Returns true if the vector is empty/ m_values==nullptr
 *
 * @return true if the vector is empty and all values nullptr.  false
 * otherwise.
 */
    bool IsEmpty() const {
        OPENFHE_THROW("IsEmpty not implemented");
    }

    /**
 * @brief Make the element Sparse for SHE KeyGen operations.
 * Sets every index not equal to zero mod the wFactor to zero.
 *
 * @param &wFactor ratio between the original element's ring dimension and the
 * new ring dimension.
 */
    void MakeSparse(uint32_t wFactor) {
        OPENFHE_THROW("MakeSparse not implemented");
    }

    /**
 * @brief Calculate Element mod 2
 *
 * @return result of performing a mod-2 operation on the element.
 */
    DCRTModuleType ModByTwo() const {
        OPENFHE_THROW("ModByTwo not implemented");
    }

    /**
 * @brief Calculate and return the Multiplicative Inverse of the element
 * @return the multiplicative inverse of the element, if it exists.
 */
    DCRTModuleType MultiplicativeInverse() const {
        OPENFHE_THROW("MultiplicativeInverse not implemented");
    }

    /**
 * @brief Scalar multiplication followed by division and rounding operation -
 * operation on all entries.
 *
 * @param &p is the integer muliplicand.
 * @param &q is the integer divisor.
 * @return is the return value of the multiply, divide and followed by
 * rounding operation.
 */
    DCRTModuleType MultiplyAndRound(const Integer& p, const Integer& q) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i].MultiplyAndRound(p, q);
        }
        return tmp;
    }

    /**
 * @brief Calculate a vector of elements by raising the base element to
 * successive powers
 *
 * @param baseBits
 * @return
 */
    std::vector<DCRTModuleType> PowersOfBase(usint baseBits) const {
        OPENFHE_THROW("PowersOfBase not implemented");
    }

    /**
 * @brief Mod - perform a modulus operation.
 * Does proper mapping of [-modulus/2, modulus/2) to [0, modulus).
 *
 * @param modulus is the modulus to use.
 * @return is the return value of the modulus.
 */
    DCRTModuleType Mod(const Integer& modulus) const {
        DCRTModuleType tmp(m_params, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i].Mod(modulus);
        }
        return tmp;
    }

    DCRTPolyType GetDCRTPolyAt(uint32_t index) const {
        return m_vectors[index];
    }

    DCRTModuleType DropRows(uint32_t rowsToDrop, DCRTModuleType& removed) const {
        if (rowsToDrop >= m_moduleRows) {
            OPENFHE_THROW("DropRows rows to drop is >= current rows");
        }

        DCRTModuleType reduced(m_params, m_format, false, m_moduleRows - rowsToDrop, m_moduleCols);
        for (usint row = 0; row < m_moduleRows - rowsToDrop; row++) {
            for (usint col = 0; col < m_moduleCols; col++) {
                reduced.m_vectors[row * m_moduleCols + col] = m_vectors[row * m_moduleCols + col];
            }
        }

        removed = DCRTModuleType(m_params, m_format, false, rowsToDrop, m_moduleCols);
        for (usint row = 0; row < rowsToDrop; row++) {
            for (usint col = 0; col < m_moduleCols; col++) {
                removed.m_vectors[row * m_moduleCols + col] =
                    m_vectors[(m_moduleRows - rowsToDrop + row) * m_moduleCols + col];
            }
        }
        return reduced;
    }

    DCRTModuleType DropColumns(uint32_t columnsToDrop, DCRTModuleType& removed) const {
        if (columnsToDrop >= m_moduleCols) {
            OPENFHE_THROW("DropRows rows to drop is >= current rows");
        }

        DCRTModuleType reduced(m_params, m_format, false, m_moduleRows, m_moduleCols - columnsToDrop);
        for (usint row = 0; row < m_moduleRows; row++) {
            for (usint col = 0; col < m_moduleCols - columnsToDrop; col++) {
                reduced.m_vectors[row * (m_moduleCols - columnsToDrop) + col] = m_vectors[row * m_moduleCols + col];
            }
        }

        removed = DCRTModuleType(m_params, m_format, false, m_moduleRows, columnsToDrop);
        for (usint row = 0; row < m_moduleRows; row++) {
            for (usint col = 0; col < columnsToDrop; col++) {
                removed.m_vectors[row * (m_moduleCols - columnsToDrop) + col] =
                    m_vectors[row * m_moduleCols + m_moduleCols - columnsToDrop + col];
            }
        }
        return reduced;
    }

    /**
 * @brief Switch modulus and adjust the values
 *
 * @param &modulus is the modulus to be set.
 * @param &rootOfUnity is the corresponding root of unity for the modulus
 * @param &modulusArb is the modulus used for arbitrary cyclotomics CRT
 * @param &rootOfUnityArb is the corresponding root of unity for the modulus
 * ASSUMPTION: This method assumes that the caller provides the correct
 * rootOfUnity for the modulus.
 */
    void SwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                       const Integer& rootOfUnityArb) {
        OPENFHE_THROW("SwitchModulus not implemented");
    }

    /**
 * @brief onvert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
 */
    void SwitchFormat() {
        m_format = (m_format == Format::COEFFICIENT) ? Format::EVALUATION : Format::COEFFICIENT;
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            m_vectors[i].SwitchFormat();
    }

    std::string SerializedObjectName() const override {
        return "DCRTModule";
    }

    inline const std::shared_ptr<Params>& GetParams() const {
        return m_params;
    }

    const PolyType& GetElementAtIndex(size_t row, size_t col, usint i) const {
        return m_vectors[row * m_moduleCols + col].GetElementAtIndex(i);
    }

    void SetElementAtIndex(size_t row, size_t col, usint index, const PolyType& element) {
        m_vectors[row * m_moduleCols + col].SetElementAtIndex(index, element);
    }

    DCRTModuleType ApproxSwitchCRTBasis(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                                        const std::vector<NativeInteger>& QHatInvModq,
                                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                                        const std::vector<DoubleNativeInt>& modpBarrettMu) const {
        DCRTModuleType tmp(paramsP, m_format, false, m_moduleRows, m_moduleCols);
        size_t size{m_vectors.size()};
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (usint i = 0; i < size; i++) {
            tmp.m_vectors[i] = m_vectors[i].ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon,
                                                                 QHatModp, modpBarrettMu);
        }
        return tmp;
    }

    std::shared_ptr<Params> GetExtendedCRTBasis(const std::shared_ptr<Params>& paramsP) const {
        size_t sizeQ  = m_params->GetParams().size();
        size_t sizeQP = sizeQ + paramsP->GetParams().size();
        std::vector<NativeInteger> moduliQP(sizeQP);
        std::vector<NativeInteger> rootsQP(sizeQP);
        const auto& parq = m_params->GetParams();
        for (size_t i = 0; i < sizeQ; ++i) {
            moduliQP[i] = parq[i]->GetModulus();
            rootsQP[i]  = parq[i]->GetRootOfUnity();
        }
        const auto& parp = paramsP->GetParams();
        for (size_t i = sizeQ, j = 0; i < sizeQP; ++i, ++j) {
            moduliQP[i] = parp[j]->GetModulus();
            rootsQP[i]  = parp[j]->GetRootOfUnity();
        }
        return std::make_shared<Params>(2 * m_params->GetRingDimension(), moduliQP, rootsQP);
    }

protected:
    /**
   * @brief ostream operator
   * @param os the input preceding output stream
   * @param vec the element to add to the output stream.
   * @return a resulting concatenated output stream
   */
    friend inline std::ostream& operator<<(std::ostream& os, const DCRTModuleType& vec) {
        // os << (vec.m_format == EVALUATION ? "EVAL: " : "COEF: ");
        for (usint i = 0; i < vec.m_vectors.size(); i++) {
            if (i != 0)
                os << std::endl;
            os << i << ": ";
            os << vec.m_vectors[i] << "||";
        }
        return os;
    }

    /**
   * @brief Element-element addition operator.
   * @param a first element to add.
   * @param b second element to add.
   * @return the result of the addition operation.
   */
    friend inline DCRTModuleType operator+(const DCRTModuleType& a, const DCRTModuleType& b) {
        return a.Plus(b);
    }
    /**
   * @brief Element-integer addition operator.
   * @param a first element to add.
   * @param b integer to add.
   * @return the result of the addition operation.
   */
    friend inline DCRTModuleType operator+(const DCRTModuleType& a, const Integer& b) {
        return a.Plus(b);
    }

    /**
   * @brief Integer-element addition operator.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
    friend inline DCRTModuleType operator+(const Integer& a, const DCRTModuleType& b) {
        return b.Plus(a);
    }

    /**
   * @brief Element-integer addition operator with CRT integer.
   * @param a first element to add.
   * @param b integer to add.
   * @return the result of the addition operation.
   */
    friend inline DCRTModuleType operator+(const DCRTModuleType& a, const std::vector<Integer>& b) {
        return a.Plus(b);
    }

    /**
   * @brief Integer-element addition operator with CRT integer.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
    friend inline DCRTModuleType operator+(const std::vector<Integer>& a, const DCRTModuleType& b) {
        return b.Plus(a);
    }

    /**
   * @brief Element-element subtraction operator.
   * @param a element to subtract from.
   * @param b element to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DCRTModuleType operator-(const DCRTModuleType& a, const DCRTModuleType& b) {
        return a.Minus(b);
    }

    /**
   * @brief Element-integer subtraction operator with CRT integer.
   * @param a first element to subtract.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DCRTModuleType operator-(const DCRTModuleType& a, const std::vector<Integer>& b) {
        return a.Minus(b);
    }

    /**
   * @brief Integer-element subtraction operator with CRT integer.
   * @param a integer to subtract.
   * @param b element to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DCRTModuleType operator-(const std::vector<Integer>& a, const DCRTModuleType& b) {
        return b.Minus(a);
    }

    /**
   * @brief Element-integer subtraction operator.
   * @param a element to subtract from.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DCRTModuleType operator-(const DCRTModuleType& a, const Integer& b) {
        return a.Minus(b);
    }

    /**
   * @brief Element-element multiplication operator.
   * @param a element to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(const DCRTModuleType& a, const DCRTModuleType& b) {
        return a.Times(b);
    }

    /**
   * @brief Element-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(const DCRTModuleType& a, const Integer& b) {
        return a.Times(b);
    }

    /**
   * @brief Element-CRT number multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply, in CRT format.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(const DCRTModuleType& a, const std::vector<Integer>& b) {
        return a.Times(b);
    }

    /**
   * @brief Integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(const Integer& a, const DCRTModuleType& b) {
        return b.Times(a);
    }

    /**
   * @brief Element-signed-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(const DCRTModuleType& a, int64_t b) {
        return a.Times((NativeInteger::SignedNativeInt)b);
    }

    /**
   * @brief signed-Integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DCRTModuleType operator*(int64_t a, const DCRTModuleType& b) {
        return b.Times((NativeInteger::SignedNativeInt)a);
    }

protected:
    std::shared_ptr<Params> m_params{std::make_shared<Params>()};
    Format m_format{Format::EVALUATION};
    std::vector<DCRTPolyType> m_vectors;
    uint32_t m_moduleRows{1};
    uint32_t m_moduleCols{1};
};

}  // namespace lbcrypto

#endif
