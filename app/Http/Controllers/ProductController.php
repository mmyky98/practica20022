<?php

namespace App\Http\Controllers;

use App\Models\Category;
use App\Models\Product;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

/**
 *
 */
class ProductController extends ApiController
{
    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function getAll(Request $request): JsonResponse
    {
        try {
            $products = Product::query();

            $perPage = $request->get('perPage', 20);
            $search = $request->get('search', '');

            if ($search && $search !== '') {
                $products = $products->where(function ($query) use ($search) {
                    $query->where('name', 'LIKE', '%' . $search . '%')
                        ->orWhere('description', 'LIKE', '%' . $search . '%');
                });
            }

            $categoryId = $request->get('category');

            if ($categoryId) {
                $products = $products->where('category_id', $categoryId);
            }

            $status = $request->get('status');

            if ($status) {
                $products = $products->where('status', $status);
            }

            $products = $products->paginate($perPage);

            $results = [
                'data' => $products->items(),
                'currentPage' => $products->currentPage(),
                'perPage' => $products->perPage(),
                'total' => $products->total(),
                'hasMorePages' => $products->hasMorePages()
            ];

            return $this->sendResponse($results);
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //get
    public function get($id): JsonResponse
    {
        try {
            $products = Product::find($id);

            if (!$products) {
                return $this->sendError('Product not found!', [], Response::HTTP_NOT_FOUND);
            }

            return $this->sendResponse($products->toArray());
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //adaugare

    public function add(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required|max:50',
                'category_id' => 'nullable|exists:categories,id',
                'description' =>'required',
                'quantity' =>'required',
                'price' =>'required',
                'image' =>'nullable'
            ]);

            if ($validator->fails()) {
                return $this->sendError('Bad request!', $validator->messages()->toArray());
            }

            $name = $request->get('name');
            $category_id = $request->get('category_id');
            $description = $request->get('description');
            $quantity = $request->get('quantity');
            $price = $request->get('price');
            $image = $request->get('image');

            if ($category_id) {
                $parent = Category::find($category_id);

                if ($parent->parent?->parent) {
                    return $this->sendError('You can\'t add a 3rd level subcategory!');
                }
            }

            $products = new Product();
            $products->name = $name;
            $products->category_id = $category_id;
            $products->description = $description;
            $products->quantity = $quantity;
            $products->price = $price;
            $products->image = $image;
            $products->save();

            return $this->sendResponse($products->toArray());
        } catch (\Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!');
        }
    }

    //update

    public function update($id, Request $request): JsonResponse
    {
        try {
            $products = Product::find($id);

            if (!$products) {
                return $this->sendError('Product not found!', [], Response::HTTP_NOT_FOUND);
            }

            $validator = Validator::make($request->all(), [
                'name' => 'required|max:50',
                'category_id' => 'nullable|exists:categories,id',
                'description' =>'required',
                'quantity' =>'required',
                'price' =>'required',
                'image' =>'nullable'
            ]);

            if ($validator->fails()) {
                return $this->sendError('Bad request!', $validator->messages()->toArray());
            }

            $name = $request->get('name');
            $category_id = $request->get('category_id');
            $description = $request->get('description');
            $quantity = $request->get('quantity');
            $price = $request->get('price');
            $image = $request->get('image');

            if ($category_id) {
                $parent = Category::find($category_id);

                if ($parent->parent?->parent) {
                    return $this->sendError('You can\'t add a 3rd level subcategory!');
                }

                /*if ($category_id === $category_id->id) {
                    return $this->sendError('You can\'t add same products as parent!');
                }*/
            }

            $products->name = $name;
            $products->category_id = $category_id;
            $products->description = $description;
            $products->quantity = $quantity;
            $products->price = $price;
            $products->image = $image;
            $products->update();

            return $this->sendResponse($products->toArray());
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //delete
    public function delete($id): JsonResponse
    {
        try {
            $products = Product::find($id);

            if (!$products) {
                return $this->sendError('Category not found!', [], Response::HTTP_NOT_FOUND);
            }

            DB::beginTransaction();

            $products->delete();

            DB::commit();

            return $this->sendResponse([], Response::HTTP_NO_CONTENT);
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function upload(Request $request)
    {
        if ($request->has('image')) {
            $file = $request->file('image');

            $filename = 'P'.time().'.'.$file->getClientOriginalExtension();

            $path = 'products/';

            Storage::putFileAs($path, $file, $filename);

            return $path.$filename;
        }
    }

    public function getAllProductsForCategory($categoryId)
    {
        $products = Product::where('category_id', $categoryId)
            ->orWhereHas('category', function ($query) use ($categoryId) {
               $query->where('parent_id', $categoryId)
                   ->orWhereHas('parent', function ($query) use ($categoryId) {
                       $query->where('parent_id', $categoryId);
                   });
            })->get();

//        $categories = [$categoryId];
//
//        $category = Category::find($categoryId);
//
//        if (count($category->childs) > 0) {
//            foreach ($category->childs as $subCategory) {
//                $categories[] = $subCategory->id;
//
//                if (count($subCategory->childs) > 0) {
//                    foreach ($subCategory->childs as $subSubCategory) {
//                        $categories[] = $subSubCategory->id;
//                    }
//                }
//            }
//        }
//
//        $products = Product::whereIn('category_id', $categories)->get();

        return $products->toArray();
    }
}
