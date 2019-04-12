package edu.purdue.cuttlefish.evaluation.tpch.ptxt

import edu.purdue.cuttlefish.evaluation.tpch.PtxtQuery
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions.{countDistinct, udf}

class Q16(spark: SparkSession) extends PtxtQuery(spark) {

    override def execute() = {
        import spark.implicits._

        val complains = udf { (x: String) => x.matches(".*Customer.*Complaints.*") }
        val polished = udf { (x: String) => x.startsWith("MEDIUM POLISHED") }
        val numbers = udf { (x: Int) => x.toString().matches("49|14|23|45|19|3|36|9") }

        val fparts = part
          .filter(($"p_brand" =!= "Brand#45") && !polished($"p_type") &&
            numbers($"p_size"))
          .select($"p_partkey", $"p_brand", $"p_type", $"p_size")

        val q = supplier
          .filter(!complains($"s_comment"))
          // .select($"s_suppkey")
          .join(partsupp, $"s_suppkey" === partsupp("ps_suppkey"))
          .select($"ps_partkey", $"ps_suppkey")
          .join(fparts, $"ps_partkey" === fparts("p_partkey"))
          .groupBy($"p_brand", $"p_type", $"p_size")
          .agg(countDistinct($"ps_suppkey").as("supplier_count"))
          .sort($"supplier_count".desc, $"p_brand", $"p_type", $"p_size")

        getResults(q)
    }
}
