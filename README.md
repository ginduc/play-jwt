Play-JWT
========
Token authentication for Play Framework (2.3.8) using JsonWebToken (nimbus-jose-jwt)

# Usage

### Update your sbt build file

    resolvers += Resolver.url("dynobjx-releases", url("http://ginduc.github.com/releases/"))(Resolver.ivyStylePatterns)

    libraryDependencies ++= Seq(
      "dynobjx" %% "play-jwt" % "0.1.0"
    )
    
### Set the playjwt configs in conf/application.conf

    playjwt.sharedSecret="mySharedSecret"
    playjwt.issuer="myIssuer"
    playjwt.expiryInSecs=86400
    playjwt.audience="myAudience"
    playjwt.realm="myProtectedRealm"
    
### Create signed tokens upon user authentication

    val token = JWTSession.sign(Json.obj("username" -> "nedflanders", "id" -> "6215342"))
    Ok(Json.obj("token" -> token))
    
### Verify signed tokens for each protected endpoint

    def index = Signed { implicit request =>
      println("--- whoami: " + request.userInfo)
      Ok()
    }

# Todos

### Tests!
