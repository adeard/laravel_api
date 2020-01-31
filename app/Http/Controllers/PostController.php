<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Post;
use Auth;
use App\Helpers\Api;

class PostController extends Controller
{
    public function __construct()
    {
        $this->status   = "true";
        $this->data     = [];
        $this->errorMsg = null;
    }   

    public function index(Request $request) {
        try {
            $query = Post::paginate();
            if($request->has('limit'))
                $query = Post::paginate($request->limit);

            $this->data = $query;
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 201);
    }

    public function store(Request $request) {
        try {
            $validator = Validator::make($request->all(), [
                'title' => 'required|string|max:255',
                'content' => 'required|string|max:255',
                'created_by' => 'required|integer|max:255',
            ]);
    
            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }
            
            $post =  Post::create([
                'title' => $request->title,
                'content' => $request->content,
                'created_by' => $request->created_by,
            ]);
            
            $this->data = $post;
            
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 201);
    }

    public function getDetail($id = null) {
        try {
            $this->data = Post::find($id);
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

    public function update(Request $request, $id) {
        try {
            
            $validator = Validator::make($request->all(), [
                'title' => 'required|string|max:255',
                'content' => 'required|string|max:255'
            ]);
    
            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }

            $update = Post::where('id', $id)->update($request->all());

            $this->data = Post::find($id);
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

    public function delete($id = null) {
        try{
            if(!empty($id)){
                $Obj = Post::find($id);
                $Obj->delete();
                $this->data =  $id;
            }
        }catch(\Exception $e){
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

}
