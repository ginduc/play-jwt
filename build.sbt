name := """play-jwt"""

version := "0.2.1"

isSnapshot := true

organization := "dynobjx"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.1"

libraryDependencies ++= Seq(
  "com.nimbusds" % "nimbus-jose-jwt" % "3.8.2"
)

