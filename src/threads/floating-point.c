#include "threads/floating-point.h"
#include <stdint.h>
/*we consider 17.14=p.q representation   q=14*/

const int q=14; 
const int f=1<<q;  //factor to convert between integer and string

struct real convert_int_to_real(int n)
{
     struct real x;
     x.data=n*f;
     return x;
}
int convert_real_to_int_towards_zero(struct real x)
{
    int value=x.data/f;
    return value;
}
int convert_real_to_int_towards_nearest( struct real x)
{
    int value;
    if (x.data>=0)
    {
         value=(x.data+f/2)/f;
    }
    else
    {
         value=(x.data-f/2)/f;
    }
    return value;
    
}
struct real add_real_to_real( struct real x, struct real y)
{
     struct real result;
     result.data=x.data+y.data;
     return result;
}
struct real subtract_real_from_real(struct real x,struct real y)
{
    struct real result;
     result.data=x.data-y.data;
     return result;
}
struct real add_real_to_int(struct real x,int n)
{
     struct real result;
     result.data=x.data+n*f;
     return result;
}
struct real subtract_int_from_real(struct real x,int n)
{
      struct real result;
     result.data=x.data-n*f;
     return result;
}
struct real multiply_real_by_real(struct real x,struct real y)
{
     struct real result;
     result.data=((int64_t)(x.data))*y.data/f;
     return result;
}
struct real multiply_real_by_int(struct real x,int n)
{
   struct real result;
   result.data=x.data*n;
   return result;
}
struct real divide_real_by_real(struct real x,struct real y)
{
      struct real result;
     result.data=((int64_t)(x.data))*f/y.data;
     return result;
}
struct real divide_real_by_int(struct real x,int n)
{
     struct real result;
     result.data=x.data/n;
     return result;
}