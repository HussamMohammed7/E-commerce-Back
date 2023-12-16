import Product from '../models/product'
import ApiError from '../errors/ApiError'
import { Request, Response, NextFunction } from 'express'
import product from '../models/product'

type Filter = {
  category?: string
  name?: { $regex: RegExp }
}
type SortOptions = {
  sort?: 'asc' | 'desc' | { name: number }
}
//Get ALL Products
export const getProducts = async (req: Request, res: Response, next: NextFunction) => {
  const page = Number(req.query.page) || 1
  const perPage = Number(req.query.perPage) || 3
  const products = await Product.find().populate('categories')
  const name = req.query.name
  const sort = req.query.sort
  const category = req.query.category
  const filters: Filter = {}
  const sortOptions: SortOptions = {}
  if (category && typeof category === 'string') {
    filters.category = category
  }

  if (name && typeof name === 'string') {
    filters.name = { $regex: new RegExp(name, 'i') }
  }
  if (sort && typeof sort === 'string') {
    if (sort === 'asc') {
      sortOptions.sort = { name: 1 }
    }
    if (sort === 'desc') {
      sortOptions.sort = { name: -1 }
    }
  }
  const totalProduct = await Product.countDocuments()
  const totalPages = Math.ceil(totalProduct / perPage)
  const items = await Product.find(filters)
    .skip((page - 1) * perPage)
    .limit(perPage)
    .populate('categories')

  res.status(200).json({
    msg: 'products is returned ',
    products: Product,
    page,
    perPage,
    totalProduct,
    totalPages,
    items,
  })
}
//Get product by id
export const getProductbyId = async (req: Request, res: Response) => {
  const { productId } = req.params
  try {
    const product = await Product.findById(productId)

    res.status(200).json({
      msg: "Product by Id",
      productbyId: product
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal Server Error' })
  }
}

//create  a product
export const createProduct = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description, quantity, price, image, variants, sizes, categories } = req.body;

    // Validate required fields
    if (!name || !description || !price) {
      throw new ApiError(400, 'Name, Description, and price are required');
    }

    // Create a new product instance
    const product = new Product({
      name,
      description,
      quantity,
      price,
      image,
      variants,
      sizes,
      categories,
    });

    // Save the product to the database
    await product.save();

    // Respond with success message and created product details
    res.status(201).json({
      msg: 'Product created successfully',
      product,
      category: categories,
    });
  } catch (error) {
    res.status(201).json({
      msg: 'product is updated',
      product: product,
      }  );
}}

//Update new product
export const updateProduct = async (req: Request, res: Response) => {
  const { productId } = req.params
  const { name, description, quantity, price, image, variants, size, categories } = req.body

  const product = await Product.findByIdAndUpdate(
    productId,
    {
      name: name,
      description: description,
      quantity: quantity,
      price: price,
      image: image,
      variants: variants,
      size: size,
      categories: categories,
    },
    {
      new: true,
    }
  )
  res.status(201).json({
    msg: 'product is updated',
    product: product,
  })
}
//Delete a product
export const deleteProduct = async (req: Request, res: Response, next: NextFunction) => {
  const { productId } = req.params

  try {
    const result = await Product.deleteOne({
      _id: productId,
    });
    if (result.deletedCount > 0) {
      res.status(200).send({ msg: 'Product deleted successfully' });
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
}
