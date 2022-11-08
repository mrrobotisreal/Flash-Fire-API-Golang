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
type Auth struct {
	Username string `json:"username,omitempty" bson:"username,omitempty"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
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
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering HashPassword..")
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	log.Println("Exiting HashPassword...")
	log.Println("\\__________________________________/")
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering CheckPasswordHash..")
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	log.Println("Exiting CheckPasswordHash...")
	log.Println("\\__________________________________/")
	return err == nil
}

func generateJWT(username string, email string) string {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering generateJWT..")
	claims := &JWTClaim{
		Username: username,
		Email:    email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("WinTer"))
	if err != nil {
		log.Println("Error Performing token.SignedString() Function Call..\n\n", err.Error())
		log.Println("Exiting generateJWT with errors...")
		log.Println("\\__________________________________/")
		return ""
	}
	log.Println("Exiting generateJWT successfully...")
	log.Println("\\__________________________________/")
	return tokenString
}

func validateJWT(signedToken string, username string) (err error) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering validateJWT..")
	token, err := jwt.ParseWithClaims(signedToken, &JWTClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("WinTer"), nil
	})
	if err != nil {
		log.Println("Error Performing jwt.ParseWithClaims() Function Call..\n\n", err.Error())
		log.Println("Exiting validateJWT with errors...")
		log.Println("\\__________________________________/")
		return err
	}
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		log.Println("Error Performing token.Claims.(*JWTClaim) Read/Assignment Operation..\n\n", ok)
		err = errors.New("Error Performing token.Claims.(*JWTClaim) Read/Assignment Operation..")
		log.Println("Exiting validateJWT with errors...")
		log.Println("\\__________________________________/")
		return err
	}
	if claims.Username != username {
		log.Println("Supplied username does not match claims.Username..\nJWT is not valid; returning error..\n\n")
		err = errors.New("Error: Incorrect Claims\n" +
			"One or more claims do not match the supplied information; token is not valid")
		log.Println("Exiting validateJWT with errors...")
		log.Println("\\__________________________________/")
		return err
	}
	log.Println("Exiting validateJWT successfully...")
	log.Println("\\__________________________________/")
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
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SaveSignup..")
	response.Header().Add("content-type", "application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	user.JWT = generateJWT(user.Username, user.Email)
	password, _ := HashPassword(user.Password)
	user.Password = password
	user.Collections = []Collection{}
	coll := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, err := coll.InsertOne(ctx, user)
	if err != nil {
		log.Println("Error Performing InsertOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		log.Println("Exiting SaveSignup with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting SaveSignup successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(result)
}

func CheckLogin(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering CheckLogin..")
	response.Header().Add("content-type", "application/json")
	var auth Auth
	var user User
	json.NewDecoder(request.Body).Decode(&auth)
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: auth.Username}).Decode(&user)
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting CheckLogin with errors...")
			log.Println("\\__________________________________/")
			return
		}
	}
	var authResult bool
	authResult = CheckPasswordHash(auth.Password, user.Password)
	if !authResult {
		log.Println("Failed Password Authentication..")
	} else {
		log.Println("Successful Password Authentication..")
	}
	log.Println("Exiting CheckLogin successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(authResult)
}

func GetUserCollections(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering GetUserCollections...")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n")
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n" + err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `"}`))
			log.Println("Exiting GetUserCollections with errors...")
			log.Println("\\__________________________________/")
			return
		}
	}
	log.Println("Exiting GetUserCollections successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&user)
}

func SaveCollection(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SaveCollection..")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var ic Collection
	json.NewDecoder(request.Body).Decode(&ic)
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n")
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
	}
	user.Collections = append(user.Collections, ic)
	filter := bson.D{{"username", username}}
	update := bson.D{{"$set", bson.D{{"collections", user.Collections}}}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Println("Error Performing UpdateOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
	}
	json.NewEncoder(response).Encode(result)
}

func EditCollection(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering EditCollection..")
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
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
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
		log.Println("Error Performing UpdateOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(result)
}

func CheckJWT(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering CheckJWT..")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	var incomingJWT iJWT
	json.NewDecoder(request.Body).Decode(&incomingJWT)
	if err := validateJWT(incomingJWT.Token, username); err != nil {
		switch err.Error() {
		case "Error Performing token.Claims.(*JWTClaim) Read/Assignment Operation..":
			log.Println("")
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		case "Error: Incorrect Claims\n" + "One or more claims do not match the supplied information; token is not valid":
			log.Println("CheckJWT Failure Due To Incorrect Claims..\n\n")
			// is this http code correct?
			response.WriteHeader(http.StatusNotAcceptable)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		default:
			log.Println("Error Validating JWT..\n\n")
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
	} else {
		log.Println("Successful Validation Of JWT..")
		response.WriteHeader(http.StatusOK)
		response.Write([]byte(`{ "message": "Successful Verification Of JWT" }`))
	}
}

func SetViewDate(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SetViewDate..")
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
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
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
		log.Println("Error Performing UpdateOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(&result)
}

func SetViewDateModes(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SetViewDateModes..")
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
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
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
		log.Println("Error Performing UpdateOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(&result)
}

func GetScores(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering GetScores..")
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
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
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
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SetScores..")
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

func SendTest(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SendTest..")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	mode, _ := params["mode"]
	var user User
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte("{\n" +
			`    "message": "` + err.Error() + `",` + "\n" +
			`    "where": "SendTest - FindOne Operation"` + "\n}"))
	}
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
	router.HandleFunc("/signup", SaveSignup).Methods("POST")
	router.HandleFunc("/login", CheckLogin).Methods("POST")
	router.HandleFunc("/check-jwt/{user}", CheckJWT).Methods("POST")
	router.HandleFunc("/collections/{user}", GetUserCollections).Methods("GET")
	router.HandleFunc("/collections/{user}/add", SaveCollection).Methods("POST")
	router.HandleFunc("/collections/{user}/edit", EditCollection).Methods("POST")
	router.HandleFunc("/collections/{user}/set-view-date", SetViewDate).Methods("POST")
	router.HandleFunc("/collections/{user}/set-view-date-modes", SetViewDateModes).Methods("POST")
	router.HandleFunc("/collections/{user}/scores", GetScores).Methods("GET")
	router.HandleFunc("/collections/{user}/scores/{mode}", SetScores).Methods("POST")
	router.HandleFunc("/collections/{user}/test/{mode}", SendTest).Methods("GET")
	fmt.Println("Server successfully started on port :9886...")
	http.ListenAndServe(":9886", router)
}
