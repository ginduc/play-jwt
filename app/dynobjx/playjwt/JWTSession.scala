package dynobjx.playjwt

import java.util.Date
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.{MACVerifier, MACSigner}
import com.nimbusds.jwt.{SignedJWT, JWTClaimsSet}
import play.api.libs.json.JsValue
import play.api.{Logger, Play}
import play.api.Play.current

/**
 * Created by ginduc on 2/15/15.
 */
object JWTSession {
  val tokenPrefix = "Bearer "

  private val issuer = Play.application.configuration.getString("playjwt.issuer").getOrElse("playjwt")
  private val sharedSecret = Play.application.configuration.getString("playjwt.sharedSecret")
    .getOrElse(throw new IllegalStateException("PlayJWT Shared Secret is required!"))
  private val expiryTime = Play.application.configuration.getInt("playjwt.expiryInSecs").getOrElse(60 * 60 * 24)
  private val audience = Play.application.configuration.getString("playjwt.audience").getOrElse("playjwt")
  private val signer = new MACSigner(sharedSecret)
  private val verifier = new MACVerifier(sharedSecret)
  private val algorithm = new JWSHeader(getAlgorithm)

  private def getAlgorithm = JWSAlgorithm.HS256

  def verify(token: String): Boolean = {
    val payload = decode(token)

    // Check expiration date
    if (!new Date().before(payload.getExpirationTime)) {
      Logger.error("Token expired: " + payload.getExpirationTime)
      return false
    }

    // Match Issuer
    if (!payload.getIssuer.equals(issuer)) {
      Logger.error("Issuer mismatch: " + payload.getIssuer)
      return false
    }

    // Match Audience
    if (payload.getAudience != null && payload.getAudience.size() > 0) {
      if (!payload.getAudience.get(0).equals(audience)) {
        Logger.error("Audience mismatch: " + payload.getAudience.get(0))
        return false
      }
    } else {
      Logger.error("Audience is required")
      return false
    }

    return true
  }

  def sign(userJson: JsValue): String = {
    val claimsSet = new JWTClaimsSet()
    claimsSet.setSubject(userJson.toString())
    claimsSet.setIssueTime(new Date)
    claimsSet.setIssuer(issuer)
    claimsSet.setAudience(audience)
    claimsSet.setExpirationTime(
      new Date(claimsSet.getIssueTime.getTime + (expiryTime * 1000))
    )

    val signedJWT = new SignedJWT(algorithm, claimsSet)
    signedJWT.sign(signer)
    signedJWT.serialize()
  }

  def decode(token: String) = {
    val signedJWT = SignedJWT.parse(token.substring(tokenPrefix.length))

    if (!signedJWT.verify(verifier)) {
      throw new IllegalArgumentException("Json Web Token cannot be verified!")
    }

    signedJWT.getJWTClaimsSet
  }

  def signAuthorizationToken(user: JsValue) = JWTSession.tokenPrefix + JWTSession.sign(user)
}
