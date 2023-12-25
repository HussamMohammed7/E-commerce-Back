import { NextFunction ,Request,Response} from 'express'
import { z, ZodError } from 'zod'
import ApiError from '../errors/ApiError'
import Order from "../models/order";
import {servicesGetOrder} from "../services/order";
//-----done---
export const validateCreateOrder=(req: Request, res: Response, next: NextFunction) =>{
  console.log(req.body)
  const productSchema = z.object({
    product: z.string().length(24),
    price:z.number(),
    quantity:  z.number().default(1),
  });
  const postSchema = z.object({
    userId: z.string().length(24),
    products: z.array(productSchema),
  });
  try {
    postSchema.parse(req.body)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}
//-----done---
export const validateOrderId=(req: Request, res: Response, next: NextFunction)=>{
  const getSchema  =z.object({
   orderId : z.string().length(24)
  })
  try {
    getSchema.parse(req.params)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}
export const validateOrderStatus=(req: Request, res: Response, next: NextFunction)=>{
  const getSchema  =z.object({
   status : z.string().min(5)
  })
  try {
    getSchema.parse(req.body)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}

// export const checkOrderId=async (req: Request, res: Response, next: NextFunction)=>{
//   const {orderId}=req.params
//     if(await servicesGetOrder(orderId)){
//       next()
//     }else {
//       next(ApiError.badRequest("order not found"))
//       return
//     }
//
// }