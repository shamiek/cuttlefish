package edu.purdue.cuttlefish.evaluation.tpch.ptxt

import edu.purdue.cuttlefish.evaluation.tpch.PtxtQuery
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions.{sum, udf}

class Q19(spark: SparkSession) extends PtxtQuery(spark) {

    override def execute() = {
        import spark.implicits._

        val sm = udf { (x: String) => x.matches("SM CASE|SM BOX|SM PACK|SM PKG") }
        val md = udf { (x: String) => x.matches("MED BAG|MED BOX|MED PKG|MED PACK") }
        val lg = udf { (x: String) => x.matches("LG CASE|LG BOX|LG PACK|LG PKG") }

        val decrease = udf { (x: Double, y: Double) => x * (1 - y) }

        // project part and lineitem first?
        val q = part.join(lineitem, $"l_partkey" === $"p_partkey")
          .filter(($"l_shipmode" === "AIR" || $"l_shipmode" === "AIR REG") &&
            $"l_shipinstruct" === "DELIVER IN PERSON")
          .filter(
              (($"p_brand" === "Brand#12") &&
                sm($"p_container") &&
                $"l_quantity" >= 1 && $"l_quantity" <= 11 &&
                $"p_size" >= 1 && $"p_size" <= 5) ||
                (($"p_brand" === "Brand#23") &&
                  md($"p_container") &&
                  $"l_quantity" >= 10 && $"l_quantity" <= 20 &&
                  $"p_size" >= 1 && $"p_size" <= 10) ||
                (($"p_brand" === "Brand#34") &&
                  lg($"p_container") &&
                  $"l_quantity" >= 20 && $"l_quantity" <= 30 &&
                  $"p_size" >= 1 && $"p_size" <= 15))
          .select(decrease($"l_extendedprice", $"l_discount").as("volume"))
          .agg(sum("volume"))

        getResults(q)
    }
}
