package edu.purdue.cuttlefish.spark

import org.apache.spark.sql.SparkSession

object Config {
    val CUTTLEFISH_HOME = sys.env("CUTTLEFISH_HOME")
    // resolve this from /etc/hosts to make life easy
    val MASTER = "master"
    val SPARK_PORT = "7077"
    val HDFS_PORT = "9000"

    object FileSystem extends Enumeration {
        val LOCAL, HDFS = Value
    }

//    val fileSystem = FileSystem.LOCAL
        val fileSystem = FileSystem.HDFS

    def getDefaultSpark(appName: String = "Unnamed App", master: String = "local") = {

        val masterURL =
            if (master == "standalone" || master == "spark")
                "spark://" + Config.MASTER + ":" + Config.SPARK_PORT
            else
                master

        val spark = SparkSession
          .builder()
          .appName(appName)
//          .master(masterURL)
          .getOrCreate()
        spark.sparkContext.setLogLevel("ERROR")

        spark
    }

//    def getHDFSPath(path: String) = "hdfs://" + Config.MASTER + ":" + Config.HDFS_PORT + path
    // file system prefix will be passed from core-site.xml
    def getHDFSPath(path: String) = path

    def getLocalPath(path: String) = "file://" + path

}
