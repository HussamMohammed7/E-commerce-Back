import ApiError from '../errors/ApiError'
import { Request, Response, NextFunction } from 'express'
import User from '../models/user'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { sendActivationEmail, sendForgotPasswordEmail } from '../util/email'
import jwt from 'jsonwebtoken'

type Filter = {
  role?: 'visitor' | 'admin'
}

function generateActivationToken() {
  return crypto.randomBytes(32).toString('hex')
}

export const getAllUsers = async (req: Request, res: Response) => {
  const filter: Filter = {}

  const page = Number(req.query.page) || 1
  const perPage = Number(req.query.perPage) || 10
  const role = req.query.role
  console.log(page, perPage)

  if (role && typeof role === 'string') {
    if (role == 'admin') {
      filter.role = role
    }
    if (role == 'visitor') {
      filter.role = role
    }
  }

  const totalUsers = await User.countDocuments(filter)
  const totalPages = Math.ceil(totalUsers / perPage)

  const users = await User.find(filter)
    .skip((page - 1) * perPage)
    .limit(perPage)
    .populate('order')
    .select('-password')

  res.json({
    page,
    perPage,
    totalUsers,
    totalPages,
    users,
  })
}

// Register user a varivaction

export const register = async (req: Request, res: Response, next: NextFunction) => {
  const { first_name, last_name, email, password } = req.validatedUser
  try {
    const userExists = await User.findOne({ email })
    if (userExists) {
      return next(ApiError.badRequest('Email already registered'))
    }
    if (!first_name) {
      next(ApiError.badRequest('First name is required'))
      return
    }

    if (!last_name) {
      next(ApiError.badRequest('Last name is required'))
      return
    }

    if (!email) {
      next(ApiError.badRequest('Email is required'))
      return
    }

    if (!password) {
      next(ApiError.badRequest('Password is required'))
      return
    }

    const activationToken = generateActivationToken()
    // TODO: talk about hashing and Salt
    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = new User({
      first_name,
      last_name,
      email,
      password: hashedPassword,
      activationToken,
      role: 'visitor',
    })

    await newUser.save()
    await sendActivationEmail(email, activationToken)

    //TODO: send an email to the user for activation. the email should include the activationToken

    res.json({
      msg: 'User registered. Check your email to activate your account!',
    })
  } catch (error) {
    console.log('error:', error)
    next(ApiError.badRequest('Something went wrong'))
  }
}

export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email } = req.userForgetPassword

  try {
    const userExists = await User.findOne({ email })

    if (!userExists) {
      next(ApiError.badRequest('Email not found '))
      return
    }
    if (!userExists?.isActive) {
      next(ApiError.badRequest('Your Email in not Activated , Please Activate Your Email'))
      return
    }
  if (userExists?.forgotPasswordToken != null){
    next(ApiError.badRequest('check your email , forgot password link have been sent '))
    return
  }

    const forgotPasswordToken = generateActivationToken()
    // TODO: talk about hashing and Salt

    await User.updateOne({ email }, { forgotPasswordToken })
    await sendForgotPasswordEmail(email, forgotPasswordToken)

    //TODO: send an email to the user for activation. the email should include the activationToken

    res.json({
      msg: 'Check your Email to reset your password ',
    })
  } catch (error) {
    console.log('error:', error)
    next(ApiError.badRequest('Something went wrong'))
  }
}

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const password = req.resetForgetPassword.password
  const forgotPasswordToken = req.resetForgetPassword.forgotPasswordToken

  const hashedPassword = await bcrypt.hash(password, 10)

  const user = await User.findOne({ forgotPasswordToken })

  user.password = hashedPassword
  user.forgotPasswordToken = undefined

  await user.save()

  res.status(200).json({
    msg: 'password is reset',
  })
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.validatedLoginUser
  try {
    const user = await User.findOne({ email }).exec()

    if (!user) {
      return res.status(401).json({
        msg: 'User is not found ',
      })
    }
    // to compare hash password with the login passowrd
    bcrypt.compare(password, user.password, async (err, isPassCorrect) => {
      if (err) {
        return res.status(401).json({
          msg: 'Login failed',
        })
      }
      if (isPassCorrect) {
        const token = jwt.sign(
          {
            email: user.email,
            _id: user._id,
            role: user.role,
          },
          process.env.TOKEN_SECRET as string,
          {
            expiresIn: '24h',
          }
        )
        const userWithoutPassword = await User.findOne({ email }).select('-password')

        return res.status(200).json({
          msg: 'Login is successful',
          token: token,
          user: userWithoutPassword,
        })
      } else {
        return res.status(401).json({
          msg: 'Password is not correct',
        })
      }
    })
  } catch (error) {
    console.log('Error in login', error)
    return res.status(500).json({
      message: 'Cannot find user',
    })
  }
}

export const activation = async (req: Request, res: Response, next: NextFunction) => {
  const activationToken = req.params.activationToken
  const user = await User.findOne({ activationToken })

  if (!user) {
    next(ApiError.badRequest('Invalid activation token'))
    return
  }

  user.isActive = true
  user.activationToken = undefined

  await user.save()

  res.status(200).json({
    msg: 'Account activated successfully',
  })
}

export const getOneUser = async (req: Request, res: Response) => {
  const userId = req.params.userId
  const user = await User.findById(userId).populate('order').select('-password')

  res.status(200).json(user)
}

export const DeleteOneUser = async (req: Request, res: Response) => {
  const { userId } = req.params

  const deleteUser = await User.deleteOne({
    _id: userId,
  })
  if (deleteUser['deletedCount'] === 1) {
    res.json({
      msg: 'User delete it Successfully done',
    })
  } else {
    res.json({
      msg: 'User not found',
    })
  }
}

export const addAddress = async (req: Request, res: Response) => {
  try {
    const userId  = req.params.userId;
    const { name, country, city, address, phone } = req.body;

    // Validate input here (e.g., presence of required fields, data types, etc.)

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        msg: 'User not found',
      });
    }

    // Assuming 'address' is an array field in the User model
    user.address.push({ name, country, city, address, phone });

    const updatedUser = await user.save();

    res.json({
      user: updatedUser,
    });
  } catch (error) {
    console.error('Error adding address:', error);
    res.status(500).json({
      msg: 'Internal server error',
    });
  }
};
export const deleteAddress = async (req: Request, res: Response) => {
  const userId = req.params.userId; // Assuming you have a user object in your request (e.g., from authentication middleware)
  const addressId = req.params.addressId;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        msg: 'User not found',
      });
    }

    // Find the index of the address with the given addressId
    const addressIndex = user.address.findIndex((addr: { id: string }) => addr.id === addressId);

    if (addressIndex === -1) {
      return res.status(404).json({
        msg: 'Address not found',
      });
    }

    // Remove the address from the array
    user.address.splice(addressIndex, 1);

    // Save the updated user
    await user.save();

    return res.json({
      msg: 'Address deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting address:', error);
    return res.status(500).json({
      msg: 'Internal Server Error',
    });
  }
};
export const updateUser = async (req: Request, res: Response) => {
  const first_name = req.body.first_name
  const last_name = req.body.last_name
  const avatar = req.body.avatar
  const userId = req.params.userId
  const role = req.body.role
  const isActive = req.body.isActive

  const newUser = await User.findByIdAndUpdate(
    userId,
    {
      first_name,
      last_name,
      avatar,
      role,
      isActive,
    },
    {
      new: true,
    }
  ).select('-password')
  if (!newUser) {
    res.json({
      msg: 'User not found',
    })
    return
  }

  res.json({
    user: newUser,
  })
}

export const addOneUser = async (req: Request, res: Response, next: NextFunction) => {
  const { first_name, last_name, email, password, role } = req.body

  if (!first_name || !last_name || !email || !password || !role) {
    next(ApiError.badRequest('All user details are required'))
    return
  }

  const newUser = new User({ first_name, last_name, email, password, role })
  await newUser.save()

  res.json({
    msg: 'done',
    users: newUser,
  })
}
