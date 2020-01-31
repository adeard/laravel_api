<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Comment;
use Auth;
use App\Helpers\Api;

class CommentController extends Controller
{
    public function __construct()
    {
        $this->status   = "true";
        $this->data     = [];
        $this->errorMsg = null;
    }   

    public function index(Request $request) {
        try {
            $query = Comment::paginate();
            if($request->has('limit'))
                $query = Comment::paginate($request->limit);

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
                'comments' => 'required|string|max:255',
                'user_id' => 'required|integer|max:255',
                'article_id' => 'required|integer|max:255',
            ]);
    
            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }
            
            $post =  Comment::create([
                'comments' => $request->comments,
                'user_id' => $request->user_id,
                'article_id' => $request->article_id,
            ]);
            
            $this->data = $post;
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 201);
    }

    public function detail($id = null) {
        try {
            $this->data = Comment::find($id);
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

    public function update(Request $request, $id) {
        try {
            
            $validator = Validator::make($request->all(), [
                'comments' => 'required|string|max:255',
                'user_id' => 'required|integer|max:255',
                'article_id' => 'required|integer|max:255',
            ]);
    
            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }

            $update = Comment::where('id', $id)->update($request->all());

            $this->data = Comment::find($id);
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

    public function delete($id = null) {
        try{
            if(!empty($id)){
                $Obj = Comment::find($id);
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
