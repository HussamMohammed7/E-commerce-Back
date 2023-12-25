import express from 'express'
const router = express.Router()
import { createProduct, deleteProduct, getProducts, getProductbyId, updateProduct } from '../controllers/productController'
import { validateProduct } from '../middlewares/validateProduct'
import { checkAuth } from '../middlewares/checkAuth'

//Get product 
router.get('/', getProducts)
//Get product By id
router.get('/:productId', getProductbyId)
//Create new product 
router.post('/', validateProduct, createProduct)
//Update new product 
router.put('/:productId', validateProduct, updateProduct)
//Delte product 
router.delete('/:productId', deleteProduct)
export default router
