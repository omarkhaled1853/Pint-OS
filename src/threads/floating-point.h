#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>       


struct real     // It does not need a struct but just to separate concept of Integer away from real
{
    int data;
};



struct real convert_int_to_real(int n);      //converts int value to real one
int convert_real_to_int_towards_zero(struct real x);  // round towards zero  (read the difference between both rounds at blog of stanford)
int convert_real_to_int_towards_nearest( struct real x); // round towards the nears
struct real add_real_to_real( struct real x, struct real y);  // adding real to real
struct real subtract_real_from_real(struct real x,struct real y); // X-Y real minus another
struct real add_real_to_int(struct real x,int n);  //add real to int 
struct real subtract_int_from_real(struct real x,int n);  // subtract X-n  real from int
struct real multiply_real_by_real(struct real x,struct real y); // X.Y
struct real multiply_real_by_int(struct real x,int n);   //X.n
struct real divide_real_by_real(struct real x,struct real y);  // X/Y
struct real divide_real_by_int(struct real x,int n);  // X/n


#endif