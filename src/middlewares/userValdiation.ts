import zod, { ZodError } from 'zod'
import { NextFunction, Request, Response } from 'express'

import ApiError from '../errors/ApiError'

export function validateUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    email: zod.string().email(),
    password: zod.string().min(6),
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