package dynobjx.playjwt

import java.util.Date
import scala.concurrent.Future
import play.api.mvc._
import play.api.mvc.Results._
import play.api.Play
import play.api.Play.current
import play.api.libs.json.JsValue
import com.nimbusds.jose.crypto.{MACSigner, MACVerifier}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

/**
 * JSON Web Token-based authentication
 *
 * Created by ginduc on 2/12/15.
 */
class AuthenticatedRequest[A](val jwt: String,
  request: Request[A]) extends WrappedRequest[A](request)

object Authenticated extends ActionBuilder[AuthenticatedRequest] {
  def invokeBlock[A](req: Request[A], block: (AuthenticatedRequest[A]) => Future[Result]) = {
    req.headers.get("Authorization") match {
      case None => Future.successful(Unauthorized.withHeaders("WWW-Authenticate" -> """Basic realm="API Realm""""))
      case Some(token) => {
        if (JWTSession.verify(token)) {
          block(new AuthenticatedRequest(token, req))
        } else {
          Future.successful(Forbidden)
        }
      }
    }
  }
}

object JWTSession {
  val tokenPrefix = "Bearer "

  private val issuer = Play.application.configuration.getString("playjwt.issuer").getOrElse("playjwt")
  private val sharedSecret = Play.application.configuration.getString("playjwt.sharedSecret")
    .getOrElse(throw new IllegalStateException("PlayJWT Shared Secret is required!"))
  private val expiryTime = Play.application.configuration.getInt("playjwt.expiryInSecs").getOrElse(60 * 60 * 24)
  private val audience = Play.application.configuration.getString("playjwt.audience").getOrElse("playjwt")
  private val signer = new MACSigner(sharedSecret)
  private val verifier = new MACVerifier(sharedSecret)
  private val algorithm = new JWSHeader(JWSAlgorithm.HS256)

  def verify(token: String): Boolean = {
    val jwt = token.substring(tokenPrefix.length)
    val signedJWT = SignedJWT.parse(jwt)
    val payload = signedJWT.getJWTClaimsSet

    // Check expiration date
    if (!new Date().before(payload.getExpirationTime)) {
      println("Token expired: " + payload.getExpirationTime)
      return false
    }

    // Match Issuer
    if (!payload.getIssuer.equals(issuer)) {
      println("Issuer mismatch: " + payload.getIssuer)
      return false
    }

    // Match Audience
    if (payload.getAudience != null && payload.getAudience.size() > 0) {
      if (!payload.getAudience.get(0).equals(audience)) {
        println("Audience mismatch: " + payload.getAudience.get(0))
        return false
      }
    } else {
      println("Audience is required")
      return false
    }

    signedJWT.verify(verifier)
  }

  def signToken(userJson: JsValue): String = {
    val currDate = new Date()
    val expiryDate = currDate.getTime + (expiryTime * 1000)
    val claimsSet = new JWTClaimsSet()
    claimsSet.setSubject(userJson.toString())
    claimsSet.setIssueTime(currDate)
    claimsSet.setIssuer(issuer)
    claimsSet.setAudience(audience)
    claimsSet.setExpirationTime(new Date(expiryDate))

    val signedJWT = new SignedJWT(algorithm, claimsSet)
    signedJWT.sign(signer)
    signedJWT.serialize()
  }
}

trait PlayJWTImplicits {
  implicit class AuthenticatedResult(result: Result) {
    def withPlayJWTSession(user: JsValue)(implicit request: RequestHeader): Result = {
      result.withHeaders("Authorization" -> (JWTSession.tokenPrefix + JWTSession.signToken(user)))
    }
  }
}
