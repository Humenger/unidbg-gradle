package org.aeonlucid;



import org.junit.Test;

import java.io.File;

public class PathTest {
    @Test
    public void testPath(){
        System.out.println(new File("./").getAbsolutePath());
    }

    public static void main(String[] args) {
        new PathTest().testPath();
    }
}
