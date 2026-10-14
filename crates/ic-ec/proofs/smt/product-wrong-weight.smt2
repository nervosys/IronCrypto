; A negative control: product.smt2 with one term at the wrong weight,
; a1 b2 at 2^(64 * 4) where 2^(64 * 3) belongs. The identity is false, so the
; negation must be satisfiable: `sat`. If a solver said `unsat` here, its
; `unsat` on product.smt2 would mean nothing.

(set-logic QF_NIA)
(declare-const a0 Int) (declare-const a1 Int) (declare-const a2 Int) (declare-const a3 Int)
(declare-const b0 Int) (declare-const b1 Int) (declare-const b2 Int) (declare-const b3 Int)

(define-fun w1 () Int 18446744073709551616)
(define-fun w2 () Int (* w1 w1))
(define-fun w3 () Int (* w2 w1))
(define-fun w4 () Int (* w3 w1))
(define-fun w5 () Int (* w4 w1))
(define-fun w6 () Int (* w5 w1))

(define-fun a () Int (+ a0 (* a1 w1) (* a2 w2) (* a3 w3)))
(define-fun b () Int (+ b0 (* b1 w1) (* b2 w2) (* b3 w3)))

(define-fun schoolbook () Int
  (+ (* a0 b0)        (* a0 b1 w1)    (* a0 b2 w2)    (* a0 b3 w3)
     (* a1 b0 w1)     (* a1 b1 w2)    (* a1 b2 w4)    (* a1 b3 w4)
     (* a2 b0 w2)     (* a2 b1 w3)    (* a2 b2 w4)    (* a2 b3 w5)
     (* a3 b0 w3)     (* a3 b1 w4)    (* a3 b2 w5)    (* a3 b3 w6)))

(assert (not (= schoolbook (* a b))))
(check-sat)
