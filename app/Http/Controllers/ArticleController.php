<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Article;
use App\Comment;
use Auth;
use App\Helpers\Api;

class ArticleController extends Controller
{
    public function __construct()
    {
        $this->status   = "true";
        $this->data     = [];
        $this->errorMsg = null;
    }   

    public function index(Request $request) {
        try {
            $paginate = ($request->has('limit'))?$request->limit:10;
            $query = Article::paginate($paginate);
            if($request->role == 'admin')
                $query = Article::withCount('comments')->paginate($paginate);

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
                'user_id' => 'required|integer|max:255',
            ]);
    
            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }
            
            $post =  Article::create([
                'title' => $request->title,
                'content' => $request->content,
                'user_id' => $request->user_id,
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
            $this->data = Article::where('id', $id)->with('latestComment','latestComment.users')->get()->sortBy('latestComment.created_at');
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

            $update = Article::where('id', $id)->update($request->all());

            $this->data = Article::find($id);
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

    public function delete($id = null) {
        try{
            if(!empty($id)){
                $Obj = Article::find($id);
                if($Obj->delete())
                    Comment::where('article_id', $id)->delete();
                    
                $this->data =  $id;
            }
        }catch(\Exception $e){
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 200);
    }

}
