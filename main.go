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
	"math/rand"
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
var _en i18n
var _vi i18n
var _zh_cn i18n
var _zh_tw i18n
var _ru i18n

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
type TestCard struct {
	Question      string `json:"question"`
	Answer        string `json:"answer"`
	Photo         string `json:"photo"`
	QuestionStyle string `json:"questionStyle"`
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
type APITracking struct {
	Log        string    `json:"log,omitempty" bson:"log,omitempty"`
	Name       string    `json:"name,omitempty" bson:"name,omitempty"`
	RemoteAddr string    `json:"remoteAddr,omitempty" bson:"remoteAddr,omitempty"`
	Time       time.Time `json:"time,omitempty" bson:"time,omitempty"`
}
type UserTracking struct {
	CreationDate               time.Time `json:"creationDate,omitempty" bson:"creationDate,omitempty"`
	TotalCreatedCollections    int       `json:"totalCreatedCollections,omitempty" bson:"totalCreatedCollections,omitempty"`
	TotalCollections           int       `json:"totalCollections,omitempty" bson:"totalCollections,omitempty"`
	TotalDownloadedCollections int       `json:"totalDownloadedCollections,omitempty" bson:"totalDownloadedCollections,omitempty"`
}
type CollectionTracking struct {
	TotalTimesStudied         int `json:"totalTimesStudied,omitempty" bson:"totalTimesStudied,omitempty"`
	TotalTimesTestedEasy      int `json:"totalTimesTestedEasy,omitempty" bson:"totalTimesTestedEasy,omitempty"`
	TotalTimesTestedDifficult int `json:"totalTimesTestedDifficult,omitempty" bson:"totalTimesTestedDifficult,omitempty"`
}
type CardTracking struct {
	TimesCorrect   int `json:"timesCorrect,omitempty" bson:"timesCorrect,omitempty"`
	TimesIncorrect int `json:"timesIncorrect,omitempty" bson:"timesIncorrect,omitempty"`
}
type i18n struct {
	AppTitle                  string `json:"app-title"`
	LoginTitle                string `json:"login-title"`
	SignupTitle               string `json:"signup-title"`
	MainMenuTitle             string `json:"main-menu-title"`
	TotalCollectionsTitle     string `json:"total-collections-title"`
	CreatedAtSpan             string `json:"created-at-span"`
	LastViewSpan              string `json:"last-view-span"`
	ViewStatsButton           string `json:"view-stats-button"`
	ViewStatsTitle            string `json:"view-stats-title"`
	ViewOverallStatsButton    string `json:"view-overall-stats-button"`
	CreateNewCollectionButton string `json:"create-new-collection-button"`
	CreateCollectionTitle     string `json:"create-collection-title"`
	CollectionNameLabel       string `json:"collection-name-label"`
	CategoryLabel             string `json:"category-label"`
	AddCardsLabel             string `json:"add-cards-label"`
	AddAnImageLabel           string `json:"add-an-image-label"`
	QuestionLabel             string `json:"question-label"`
	AnswerLabel               string `json:"answer-label"`
	AddCardButton             string `json:"add-card-button"`
	TotalCardsLabel           string `json:"total-cards-label"`
	SaveCollectionButton      string `json:"save-collection-button"`
	MainMenuButton            string `json:"main-menu-button"`
	SettingsButton            string `json:"settings-button"`
	ShareButton               string `json:"share-button"`
	ThemesButton              string `json:"themes-button"`
	AccountButton             string `json:"account-button"`
	LogoutButton              string `json:"logout-button"`
	StudyScoresLabel          string `json:"study-scores-label"`
	TestGradesLabel           string `json:"test-grades-label"`
	ChooseModeTitle           string `json:"choose-mode-title"`
	StudyModeLabel            string `json:"study-mode-label"`
	LastStudiedLabel          string `json:"last-studied-label"`
	TestModeLabel             string `json:"test-mode-label"`
	LastTested                string `json:"last-tested"`
	EasyLabel                 string `json:"easy-label"`
	DifficultLabel            string `json:"difficult-label"`
	EditModeLabel             string `json:"edit-mode-label"`
	StartButton               string `json:"start-button"`
	ShowStatsButton           string `json:"show-stats-button"`
	SetTimerLabel             string `json:"set-timer-label"`
	PauseButton               string `json:"pause-button"`
	ResumeButton              string `json:"resume-button"`
	RestartButton             string `json:"restart-buttton"`
	CardNOfNTitle             string `json:"card-n-of-n-title"`
	RevealButton              string `json:"reveal-button"`
	PreviousScore             string `json:"previous-score"`
	Congratulations           string `json:"congratulations"`
	BeatPreviousScoreText     string `json:"beat-previous-score-text"`
	CheckAnswerButton         string `json:"check-answer-button"`
	GradeLabel                string `json:"grade-label"`
	WriteCorrectAnswerLabel   string `json:"write-correct-answer-label"`
	MultipleChoiceLabel       string `json:"multiple-choice-label"`
	RemoveCardButton          string `json:"remove-card-button"`
	ConfirmButton             string `json:"confirm-button"`
	AddedText                 string `json:"added-text"`
	RemovedText               string `json:"removed-text"`
	ConfirmedText             string `json:"confirmed-text"`
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
func track(tracking APITracking) {
	log.Println("<~~~API Tracking~~~>")
	fmt.Println("Fart nuggets!!!!")
	fmt.Println(tracking.RemoteAddr)
	fmt.Println(tracking.Time)
	fmt.Println(tracking.Log)
	fmt.Println(tracking.Name)
	//coll := client.Database("flash-fire-webapp").Collection("tracking")
	//ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	//_, err := coll.InsertOne(ctx, tracking)
	//if err != nil {
	//	fmt.Println("We be screwed!")
	//}
	log.Println("</~~~API Tracking~~~>")
}
func localize(key string) string {
	switch key {
	case "main-menu":
		return _en.MainMenuTitle
	default:
		return "default localization"
	}
}

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
	var tracking APITracking
	tracking.Time = time.Now()
	tracking.Name = "SaveSignup"
	tracking.RemoteAddr = request.RemoteAddr
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering SaveSignup..")
	tracking.Log = "* Entering SaveSignup\n"
	response.Header().Add("content-type", "application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	user.JWT = generateJWT(user.Username, user.Email)
	password, _ := HashPassword(user.Password)
	user.Password = password
	user.Collections = []Collection{}
	coll := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := coll.InsertOne(ctx, user)
	if err != nil {
		log.Println("Error Performing InsertOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		log.Println("Exiting SaveSignup with errors...")
		log.Println("\\__________________________________/")
		tracking.Log = tracking.Log + "* Exiting SaveSignup with errors...\n"
		track(tracking)
		return
	}
	log.Println("Exiting SaveSignup successfully...")
	log.Println("\\__________________________________/")
	tracking.Log = tracking.Log + "* Exiting SaveSignup successfully\n"
	track(tracking)
	json.NewEncoder(response).Encode(&user.JWT)
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
		// don't forget to generate new JWT here and send it back!
	}
	log.Println("Exiting CheckLogin successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(authResult)
}

func GetUserCollections(response http.ResponseWriter, request *http.Request) {
	var tracking APITracking
	tracking.Time = time.Now()
	tracking.Name = "SaveSignup"
	tracking.RemoteAddr = request.RemoteAddr
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering GetUserCollections...")
	tracking.Log = "* Entering GetUserCollections\n"
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
			tracking.Log = tracking.Log + "* Error Performing FindOne Operation | No Document Found..\n"
			response.WriteHeader(http.StatusNoContent)
		default:
			log.Println("Error Performing FindOne Operation..\n\n" + err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `"}`))
			log.Println("Exiting GetUserCollections with errors...")
			log.Println("\\__________________________________/")
			tracking.Log = tracking.Log + "* Exiting GetUserCollections with errors\n"
			tracking.Log = tracking.Log + "* Error: " + err.Error() + "\n"
			track(tracking)
			return
		}
	}
	log.Println("Exiting GetUserCollections successfully...")
	log.Println("\\__________________________________/")
	tracking.Log = tracking.Log + "* Exiting GetUserCollections successfully\n"
	track(tracking)
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
			log.Println("Exiting SaveCollection with errors...")
			log.Println("\\__________________________________/")
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
		log.Println("Exiting SaveCollection with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting SaveCollection successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&result)
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
			log.Println("Exiting EditCollection with errors...")
			log.Println("\\__________________________________/")
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
		log.Println("Exiting EditCollection with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting EditCollection successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&result)
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
			log.Println("Error Performing token.Claims.(*JWTClaim) Read/Assignment Operation..")
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting CheckJWT with errors...")
			log.Println("\\__________________________________/")
			return
		case "Error: Incorrect Claims\n" + "One or more claims do not match the supplied information; token is not valid":
			log.Println("CheckJWT Failure Due To Incorrect Claims..\n\n")
			// is this http code correct?
			response.WriteHeader(http.StatusNotAcceptable)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting CheckJWT with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Validating JWT..\n\n")
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting CheckJWT with errors...")
			log.Println("\\__________________________________/")
			return
		}
	} else {
		log.Println("Successful Validation Of JWT..")
		response.WriteHeader(http.StatusOK)
		response.Write([]byte(`{ "message": "Successful Verification Of JWT" }`))
		log.Println("Exiting CheckJWT successfully...")
		log.Println("\\__________________________________/")
		json.NewEncoder(response).Encode(true)
		return
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
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetViewDate with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetViewDate with errors...")
			log.Println("\\__________________________________/")
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
		log.Println("Exiting SetViewDate with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting SetViewDate successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&result)
	return
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
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetViewDateModes with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetViewDateModes with errors...")
			log.Println("\\__________________________________/")
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
		log.Println("Exiting SetViewDateModes with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting SetViewDateModes successfully...")
	log.Println("\\__________________________________/")
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
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting GetScores with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting GetScores with errors...")
			log.Println("\\__________________________________/")
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
	log.Println("Exiting GetScores successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&scores)
	return
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
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetScores with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting SetScores with errors...")
			log.Println("\\__________________________________/")
			return
		}
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
		log.Println("Error Performing UpdateOne Operation..\n\n", err.Error())
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		log.Println("Exiting SetScores with errors...")
		log.Println("\\__________________________________/")
		return
	}
	log.Println("Exiting SetScores successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&result)
	return
}

func GetTest(response http.ResponseWriter, request *http.Request) {
	log.Println("<<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>>")
	log.Println("Entering GetTest..")
	response.Header().Add("content-type", "application/json")
	params := mux.Vars(request)
	username, _ := params["user"]
	//mode, _ := params["mode"]
	var cnm CollectionAndMode
	var user User
	json.NewDecoder(request.Body).Decode(&cnm)
	collection := client.Database("flash-fire-webapp").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Username: username}).Decode(&user)
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			log.Println("Error Performing FindOne Operation | No Document Found..\n\n", err.Error())
			response.WriteHeader(http.StatusNoContent)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting GetTest with errors...")
			log.Println("\\__________________________________/")
			return
		default:
			log.Println("Error Performing FindOne Operation..\n\n", err.Error())
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			log.Println("Exiting GetTest with errors...")
			log.Println("\\__________________________________/")
			return
		}
	}
	//var totalNumMultipleChoice float64
	//var totalNumWriteAnswer float64
	var shuffledAnswers []TestCard
	for i := 0; i < len(user.Collections); i++ {
		if user.Collections[i].Name == cnm.Name {
			// for the future when I will assign specific amounts of each type of question
			//if len(user.Collections)%2 != 0 {
			//	totalNumMultipleChoice = math.Ceil(float64(len(user.Collections[i].CardList) / 2))
			//	totalNumWriteAnswer = math.Floor(float64(len(user.Collections[i].CardList) / 2))
			//} else {
			//	totalNumMultipleChoice = float64(len(user.Collections) / 2)
			//	totalNumWriteAnswer = float64(len(user.Collections) / 2)
			//}
			rand.Seed(time.Now().UnixNano())
			rand.Shuffle(len(user.Collections[i].CardList), func(k, l int) {
				user.Collections[i].CardList[k], user.Collections[i].CardList[l] = user.Collections[i].CardList[l], user.Collections[i].CardList[k]
			})
			for j := 0; j < len(user.Collections[i].CardList); j++ {
				var newCard TestCard
				newCard.Question = user.Collections[i].CardList[j].Question
				newCard.Answer = user.Collections[i].CardList[j].Answer
				newCard.Photo = user.Collections[i].CardList[j].Photo
				if j%2 == 0 {
					newCard.QuestionStyle = "multipleChoice"
					shuffledAnswers = append(shuffledAnswers, newCard)
				} else {
					newCard.QuestionStyle = "writtenAnswer"
					shuffledAnswers = append(shuffledAnswers, newCard)
				}
			}
			rand.Seed(time.Now().UnixNano())
			rand.Shuffle(len(shuffledAnswers), func(k, l int) {
				shuffledAnswers[k], shuffledAnswers[l] = shuffledAnswers[l], shuffledAnswers[k]
			})
			//rand.Seed(time.Now().UnixNano())
			//rand.Shuffle(len(shuffledAnswers), func(f, g int) {
			//	shuffledAnswers[f] shuffledAnswers[g] = shuffledAnswers[g] shuffledAnswers[f]
			//})
			break
		}
	}
	log.Println("Exiting GetTest successfully...")
	log.Println("\\__________________________________/")
	json.NewEncoder(response).Encode(&shuffledAnswers)
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
	//var text []byte
	data, err := os.ReadFile("_en.json")
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(data, &_en)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(localize("main-menu"))
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
	router.HandleFunc("/collections/{user}/scores", GetScores).Methods("POST")
	router.HandleFunc("/collections/{user}/scores", SetScores).Methods("POST")
	router.HandleFunc("/collections/{user}/test", GetTest).Methods("POST")
	fmt.Println("Server successfully started on port :9886...")
	http.ListenAndServe(":9886", router)
}
