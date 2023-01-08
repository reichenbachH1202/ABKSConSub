package exp.hskeys;

import it.unisa.dia.gas.jpbc.Element;

import java.text.DecimalFormat;

public class MyMatrix {
    private int row; //行数
    private int column; //列数
    private Element value[][];
    private int num;

    // 构造函数
    public MyMatrix(int row, int column, Element[][] value) {
        this.row = row;
        this.column = column;
        this.value = value;
    }
    //获取宽度，即列数
    public int widthMatrixIsCol() {
        return column;
    }
    //获取高度，即行数
    public int heightMatrixIsRow() {
        return row;
    }

    public Element[][] getValue() {
        return value;
    }

    // 乘法
    public MyMatrix multiply(MyMatrix target) throws Exception {
        if (this.column != target.row) {
            throw new Exception("The number of columns in the left matrix must equal to the number of rows in the right matrix! " +
                    "(乘法运算时左边矩阵的列数必须等于右边矩阵的行数!)");
        } else {
            Element result[][] = new Element[this.row][target.column];
            for (int i = 0; i < this.row; i++) {
                for (int j = 0; j < target.column; j++) {
                    result[i][j] = this.value[i][0].mul(target.value[0][j]);
                    for (int k = 1; k < this.column; k++) {

                        result[i][j].add(this.value[i][k].mul(target.value[k][j]));
                    }

                }
            }
            MyMatrix newMatrix = new MyMatrix(this.row, target.column, result);
            return newMatrix;
        }
    }
    //输出显示
    public static void toString(MyMatrix mymatrix){
        for(int i = 0; i < mymatrix.heightMatrixIsRow(); i++){
            for(int j = 0; j < mymatrix.widthMatrixIsCol(); j++){
                System.out.print(mymatrix.value[i][j] + ",");
            }
            System.out.println();
        }
    }
}