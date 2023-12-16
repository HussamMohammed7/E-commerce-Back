import express from 'express'

import ApiError from '../errors/ApiError'
import User from '../models/user'
import { DeleteOneUser, activation, addOneUser, getAllUsers, getOneUser, login, register, updateUser } from '../controllers/userController'
import { validateLoginUser, validateUpdateUser, validateUser, validateUserID } from '../middlewares/userValdiation'
import { checkAuth } from '../middlewares/checkAuth'
const router = express.Router()

//List all Users : work 
router.get('/',checkAuth('admin'), getAllUsers)

//List one user : work 
router.get('/:userId',validateUserID, getOneUser)


//Delete User : work
router.delete('/:userId',checkAuth('admin'),validateUserID, DeleteOneUser)


//Update user : Work
router.put('/:userId',checkAuth('admin'),validateUserID,validateUpdateUser, updateUser)

//Add User : work
router.post('/', addOneUser)




router.post('/register',validateUser, register)
router.post('/login',validateLoginUser, login)

router.get('/activateUser/:activationToken',activation)





// router.get('/:userId/page/:page', (req, res) => {
//   res.json({
//     msg: 'done',
//     user: req.user,
//   })
// })

// router.get('/', async (_, res) => {
//   const users = await User.find().populate('order')
//   res.json({
//     users,
//   })
// })

export default router


