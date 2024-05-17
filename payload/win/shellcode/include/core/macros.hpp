#ifndef HERMIT_MACROS_HPP
#define HERMIT_MACROS_HPP

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c1, out) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

#endif // HERMIT_MACROS_HPP