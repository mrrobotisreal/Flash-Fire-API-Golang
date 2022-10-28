package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

// //////////////////////////
//
//	//
//
// **"Global" Variables** //
//
//	//
//
// //////////////////////////
var client *mongo.Client

// ///////////////////////////
//
//	//
//
// **Object/Struct Types** //
//
//	//
//
// ///////////////////////////
type Card struct {
	Question string `json:"question,omitempty" bson:"question,omitempty"`
	Answer   string `json:"answer,omitempty" bson:"answer,omitempty"`
	Photo    string `json:"photo,omitempty" bson:"photo,omitempty"`
}
type Collection struct {
	Name                     string `json:"name,omitempty" bson:"name,omitempty"`
	Category                 string `json:"category,omitempty" bson:"category,omitempty"`
	CardList                 []Card `json:"cardList,omitempty" bson:"cardList,omitempty"`
	CreationDate             string `json:"creationDate,omitempty" bson:"creationDate,omitempty"`
	LastView                 string `json:"lastView,omitempty" bson:"lastView,omitempty"`
	LastViewStudy            string `json:"lastViewStudy,omitempty" bson:"lastViewStudy,omitempty"`
	MostRecentScore          int    `json:"mostRecentScore,omitempty" bson:"mostRecentScore,omitempty"`
	TotalScores              []int  `json:"totalScores,omitempty" bson:"totalScores,omitempty"`
	HighScore                int    `json:"highScore,omitempty" bson:"highScore,omitempty"`
	LastViewEasy             string `json:"lastViewEasy,omitempty" bson:"lastViewEasy,omitempty"`
	MostRecentGradeEasy      int    `json:"mostRecentGradeEasy,omitempty" bson:"mostRecentGradeEasy,omitempty"`
	TotalGradesEasy          []int  `json:"totalGradesEasy,omitempty" bson:"totalGradesEasy,omitempty"`
	HighGradeEasy            int    `json:"highGradeEasy,omitempty" bson:"highGradeEasy,omitempty"`
	LastViewDifficult        string `json:"lastViewDifficult,omitempty" bson:"lastViewDifficult,omitempty"`
	MostRecentGradeDifficult int    `json:"mostRecentGradeDifficult,omitempty" bson:"mostRecentGradeDifficult,omitempty"`
	TotalGradesDifficult     []int  `json:"totalGradesDifficult,omitempty" bson:"totalGradesDifficult,omitempty"`
	HighGradeDifficult       int    `json:"highGradeDifficult,omitempty" bson:"highGradeDifficult,omitempty"`
}
type User struct {
	Name        string       `json:"name,omitempty" bson:"name,omitempty"`
	Email       string       `json:"email,omitempty" bson:"email,omitempty"`
	Username    string       `json:"username,omitempty" bson:"username,omitempty"`
	Password    string       `json:"password,omitempty" bson:"password,omitempty"`
	JWT         string       `json:"jwt,omitempty" bson:"jwt,omitempty"`
	Collections []Collection `json:"collections,omitempty" bson:"collections,omitempty"`
}
type Scores struct {
	HighScore                int   `json:"highScore,omitempty" bson:"highScore,omitempty"`
	MostRecentScore          int   `json:"mostRecentScore,omitempty" bson:"mostRecentScore,omitempty"`
	TotalScores              []int `json:"totalScores,omitempty" bson:"totalScores,omitempty"`
	HighGradeEasy            int   `json:"highGradeEasy,omitempty" bson:"highGradeEasy,omitempty"`
	MostRecentGradeEasy      int   `json:"mostRecentGradeEasy,omitempty" bson:"mostRecentGradeEasy,omitempty"`
	TotalGradesEasy          []int `json:"totalGradesEasy,omitempty" bson:"totalGradesEasy,omitempty"`
	HighGradeDifficult       int   `json:"highGradeDifficult,omitempty" bson:"highGradeDifficult,omitempty"`
	MostRecentGradeDifficult int   `json:"mostRecentGradeDifficult,omitempty" bson:"mostRecentGradeDifficult,omitempty"`
	TotalGradesDifficult     []int `json:"totalGradesDifficult,omitempty" bson:"totalGradesDifficult,omitempty"`
}
type JWTClaim struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}
type iJWT struct {
	Token string `json:"token"`
}
type iScore struct {
	Score int    `json:"score"`
	Name  string `json:"name"`
}
type CollectionAndMode struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

// ////////////////////////
//
//	//
//
// **Helper Functions** //
//
//	//
//
// ////////////////////////
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(username string, email string) string {
	claims := &JWTClaim{
		Username: username,
		Email:    email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("WinTer"))
	if err != nil {
		fmt.Println("Error: \n", err)
		return ""
	}
	return tokenString
}

func validateJWT(signedToken string, username string) (err error) {
	token, err := jwt.ParseWithClaims(signedToken, &JWTClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("WinTer"), nil
	})
	if err != nil {
		return err
	}
	//fmt.Println("Token is motherfucking validated yo!!!!")
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		err = errors.New("couldn't parse claims sucka")
	}
	if claims.Username == username {
		fmt.Println(username)
	}
	return nil
}

func findMax(scores []int) int {
	max := scores[0]
	for _, score := range scores {
		if score > max {
			max = score
		}
	}
	return max
}

// ///////////////////////////////
//
//	//
//
// **Route Handler Functions** //
//
//	//
//
// ///////////////////////////////
func SaveSignup(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	user.JWT = generateJWT(user.Username, user.Email)
	password, _ := HashPassword(user.Password)
	user.Password = password
	user.Collections = []Collection{}
	coll := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, _ := coll.InsertOne(ctx, user)
	json.NewEncoder(response).Encode(result)
}

func CheckLogin(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	type Auth struct {
		Username string `json:"username,omitempty" bson:"username,omitempty"`
		Password string `json:"password,omitempty" bson:"password,omitempty"`
	}
	var auth Auth
	var user User
	json.NewDecoder(request.Body).Decode(&auth)
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: auth.Username}).Decode(&user)
	if err != nil {
		fmt.Println("Epic login fail!!!!")
	}
	var authResult bool
	authResult = CheckPasswordHash(auth.Password, user.Password)
	if !authResult {
		fmt.Println("ERROR processing hash result!")
	} else {
		fmt.Printf("get is sucka!!!\n%t", authResult)
	}
	json.NewEncoder(response).Encode(authResult)
}

func GetUserCollections(response http.ResponseWriter, request *http.Request) {
	log.Println("Entering GetUserCollections...")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		log.Println("Error performing FindOne operation in GetUserCollections...\n\n" + err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `"}`))
		return
	}
	json.NewEncoder(response).Encode(user)
}

func SaveCollection(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var ic Collection
	json.NewDecoder(request.Body).Decode(&ic)
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	user.Collections = append(user.Collections, ic)
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println("You done fucked up")
	}
	json.NewEncoder(response).Encode(result)
}

func EditCollection(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var updatedCollection Collection
	json.NewDecoder(request.Body).Decode(&updatedCollection)
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		fmt.Println("You done fucked up")
	}
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == updatedCollection.Name {
			user.Collections[i] = updatedCollection
			break
		}
	}
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println("You done fucked up")
	}
	json.NewEncoder(response).Encode(result)
}

func CheckJWT(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var incomingJWT iJWT
	json.NewDecoder(request.Body).Decode(&incomingJWT)
	if err := validateJWT(incomingJWT.Token, username); err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `"}`))
	} else {
		response.WriteHeader(http.StatusOK)
		response.Write([]byte(`{ "message": "Fuck yeah mofo!!! JWT done been verified yo!" }`))
	}
}

func SetViewDate(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var cname CollectionAndMode
	json.NewDecoder(request.Body).Decode(&cname)
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `", "where": "SetViewDate FindOne Operation"}`))
	}
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == cname.Name {
			user.Collections[i].LastView = time.Now().String()
		}
	}
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `", "where": "SetViewDate UpdateOne Operation" }`))
	}
	json.NewEncoder(response).Encode(&result)
}

func SetViewDateModes(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var cMode CollectionAndMode
	json.NewDecoder(request.Body).Decode(&cMode)
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `", "where": "SetViewDateModes" }`))
	}
	var updatedCollection Collection
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == cMode.Name {
			updatedCollection = user.Collections[i]
			switch cMode.Mode {
			case "study":
				updatedCollection.LastViewStudy = time.Now().String()
			case "easy":
				updatedCollection.LastViewEasy = time.Now().String()
			case "difficult":
				updatedCollection.LastViewDifficult = time.Now().String()
			}
			user.Collections[i] = updatedCollection
			break
		}
	}
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `", "where": "SetViewDateModes" }`))
	}
	json.NewEncoder(response).Encode(&result)
}

func GetScores(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	var scores Scores
	var collectionName iScore
	json.NewDecoder(request.Body).Decode(&collectionName)
	params := mux.Vars(request)
	username, _ := params["user"]
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `", "where": "GetScores" }`))
	}
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == collectionName.Name {
			scores.HighScore = user.Collections[i].HighScore
			scores.MostRecentScore = user.Collections[i].MostRecentScore
			scores.TotalScores = user.Collections[i].TotalScores
			scores.HighGradeEasy = user.Collections[i].HighGradeEasy
			scores.MostRecentGradeEasy = user.Collections[i].MostRecentGradeEasy
			scores.TotalGradesEasy = user.Collections[i].TotalGradesEasy
			scores.HighGradeDifficult = user.Collections[i].HighGradeDifficult
			scores.MostRecentGradeDifficult = user.Collections[i].MostRecentGradeDifficult
			scores.TotalGradesDifficult = user.Collections[i].TotalGradesDifficult
			break
		}
	}
	json.NewEncoder(response).Encode(&scores)
}

func SetScores(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	mode, _ := params["mode"]
	var scores iScore
	var user User
	json.NewDecoder(request.Body).Decode(&scores)
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte("{\n" +
			`    "message": "` + err.Error() + `",` + "\n" +
			`    "where": "SetScores - FindOne Operation"` + "\n}"))
	}
	var updatedCollection Collection
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == scores.Name {
			updatedCollection = user.Collections[i]
			switch mode {
			case "study":
				updatedCollection.TotalScores = append(updatedCollection.TotalScores, scores.Score)
				updatedCollection.MostRecentScore = scores.Score
				updatedCollection.HighScore = findMax(updatedCollection.TotalScores)
			case "easy":
				updatedCollection.TotalGradesEasy = append(updatedCollection.TotalGradesEasy, scores.Score)
				updatedCollection.MostRecentGradeEasy = scores.Score
				updatedCollection.HighGradeEasy = findMax(updatedCollection.TotalGradesEasy)
			case "difficult":
				updatedCollection.TotalGradesDifficult = append(updatedCollection.TotalGradesDifficult, scores.Score)
				updatedCollection.MostRecentGradeDifficult = scores.Score
				updatedCollection.HighGradeDifficult = findMax(updatedCollection.TotalGradesDifficult)
			}
			user.Collections[i] = updatedCollection
			break
		}
	}
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte("{\n" +
			`    "message": "` + err.Error() + `",` + "\n" +
			`    "where": "SetScores - UpdateOne Operation"` + "\n}"))
	}
	json.NewEncoder(response).Encode(&result)
}

// /////////////////////////////////////////
//
//	//
//
// **Point Of Entry For Code Execution** //
//
//	//
//
// /////////////////////////////////////////
func main() {
	f, err := os.OpenFile("API_LOGS.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(f)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	router := mux.NewRouter()
	router.HandleFunc("/collections/{user}", GetUserCollections).Methods("GET")
	router.HandleFunc("/signup", SaveSignup).Methods("POST")
	router.HandleFunc("/login", CheckLogin).Methods("POST")
	router.HandleFunc("/collections/{user}/add", SaveCollection).Methods("POST")
	router.HandleFunc("/collections/{user}/edit", EditCollection).Methods("POST")
	router.HandleFunc("/check-jwt/{user}", CheckJWT).Methods("POST")
	router.HandleFunc("/collections/{user}/set-view-date", SetViewDate).Methods("POST")
	router.HandleFunc("/collections/{user}/set-view-date-modes", SetViewDateModes).Methods("POST")
	router.HandleFunc("/collections/{user}/scores", GetScores).Methods("GET")
	router.HandleFunc("/collections/{user}/scores/{mode}", SetScores).Methods("POST")
	fmt.Println("Server successfully started on port :9886...")
	http.ListenAndServe(":9886", router)
}
