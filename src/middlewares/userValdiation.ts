import zod, { ZodError } from 'zod'
import { NextFunction, Request, Response } from 'express'

import ApiError from '../errors/ApiError'

export function validateUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    first_name: zod.string(),// Adjust validation as needed
    last_name: zod.string(),
    email: zod.string().email(),
    password: zod.string().min(6),
  })

  try {
    const validatedUser = schema.parse(req.body)

    req.validatedUser = validatedUser

    schema.parse(req.body)
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
export function validateUpdateUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    first_name: zod.string().optional(), // Adjust validation as needed
    last_name: zod.string().optional(),
    avatar: zod.string().url().optional(),
  })

  try {
    schema.parse(req.body)
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


export function validateLoginUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
   
    email: zod.string().email(),
    password: zod.string().min(5).max(50) // Adjust the password constraints
    
  })

  try {
    const validatedLoginUser=schema.parse(req.body)
    req.validatedLoginUser = validatedLoginUser
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
export function validateForgetUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
   
    email: zod.string().email(),
    
  })

  try {
    const userForgetPassword=schema.parse(req.body)
    req.userForgetPassword = userForgetPassword
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
export function validateResetPassword(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
   
    password: zod.string().min(5).max(50),
    forgotPasswordToken: zod.string()    
  })

  try {
    const resetForgetPassword=schema.parse(req.body)
    req.resetForgetPassword = resetForgetPassword
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

export function validateUserID(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    userId: zod.string().refine((value) => value.length === 24, {
      message: 'userId must be exactly 24 characters long',
    }),
  });

  try {
    schema.parse(req.params)
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